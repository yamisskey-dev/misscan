use crate::error::AppError;
use chrono::{DateTime, Utc};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize)]
struct ApiRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    i: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "userId")]
    user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "noteId")]
    note_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct User {
    id: String,
    username: String,
    #[serde(rename = "createdAt")]
    created_at: Option<String>,
    #[serde(rename = "notesCount")]
    notes_count: Option<u32>,
    #[serde(rename = "followersCount")]
    followers_count: Option<u32>,
    #[serde(rename = "followingCount")]
    following_count: Option<u32>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    #[serde(rename = "avatarUrl")]
    avatar_url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Note {
    id: String,
    #[serde(rename = "createdAt")]
    created_at: String,
    #[serde(default)]
    text: Option<String>,
    #[serde(rename = "userId")]
    user_id: String,
    #[serde(default)]
    user: Option<User>,
    #[serde(default)]
    #[serde(rename = "reactionCount")]
    reaction_count: Option<u32>,
    #[serde(default)]
    #[serde(rename = "repliesCount")]
    replies_count: Option<u32>,
    #[serde(default)]
    #[serde(rename = "renoteCount")]
    renote_count: Option<u32>,
}

#[derive(Debug)]
pub struct SpamIndicator {
    pub indicator_type: String,
    pub severity: Severity,
    pub description: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low => write!(f, "{}", "LOW".yellow()),
            Severity::Medium => write!(f, "{}", "MEDIUM".truecolor(255, 165, 0)),
            Severity::High => write!(f, "{}", "HIGH".red()),
            Severity::Critical => write!(f, "{}", "CRITICAL".red().bold()),
        }
    }
}

fn create_client() -> Result<Client, AppError> {
    Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("misscan/0.1.0")
        .build()
        .map_err(AppError::HttpError)
}

pub async fn detect_spam(
    instance: &str,
    token: Option<&str>,
    user_id: Option<String>,
    note_id: Option<String>,
    timeline: bool,
    limit: u32,
    verbose: bool,
) -> Result<(), AppError> {
    let client = create_client()?;
    let base_url = instance.trim_end_matches('/');

    println!("{}", "Starting spam detection...".cyan().bold());

    if let Some(ref uid) = user_id {
        analyze_user(&client, base_url, token, uid, verbose).await?;
    }

    if let Some(ref nid) = note_id {
        analyze_note(&client, base_url, token, nid, verbose).await?;
    }

    if timeline {
        analyze_timeline(&client, base_url, token, limit, verbose).await?;
    }

    if user_id.is_none() && note_id.is_none() && !timeline {
        println!("{}", "No analysis target specified. Use --user-id, --note-id, or --timeline".yellow());
    }

    Ok(())
}

async fn analyze_user(
    client: &Client,
    base_url: &str,
    token: Option<&str>,
    user_id: &str,
    verbose: bool,
) -> Result<Vec<SpamIndicator>, AppError> {
    println!("\n{} {}", "Analyzing user:".blue().bold(), user_id);

    let request = ApiRequest {
        i: token.map(String::from),
        user_id: Some(user_id.to_string()),
        note_id: None,
        limit: None,
    };

    let response = client
        .post(format!("{}/api/users/show", base_url))
        .json(&request)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(AppError::UserNotFound(user_id.to_string()));
    }

    let user: User = response.json().await?;
    let mut indicators = Vec::new();

    // Check account age
    if let Some(created_at) = &user.created_at {
        if let Ok(created) = DateTime::parse_from_rfc3339(created_at) {
            let age = Utc::now().signed_duration_since(created.with_timezone(&Utc));
            if age.num_hours() < 24 {
                indicators.push(SpamIndicator {
                    indicator_type: "NEW_ACCOUNT".to_string(),
                    severity: Severity::Medium,
                    description: "Account is less than 24 hours old".to_string(),
                    evidence: format!("Created: {}", created_at),
                });
            }
        }
    }

    // Check for high note frequency (potential spam)
    if let (Some(notes), Some(created_at)) = (user.notes_count, &user.created_at) {
        if let Ok(created) = DateTime::parse_from_rfc3339(created_at) {
            let age_hours = Utc::now()
                .signed_duration_since(created.with_timezone(&Utc))
                .num_hours() as f64;
            if age_hours > 0.0 {
                let notes_per_hour = notes as f64 / age_hours;
                if notes_per_hour > 10.0 {
                    indicators.push(SpamIndicator {
                        indicator_type: "HIGH_FREQUENCY".to_string(),
                        severity: Severity::High,
                        description: "Unusually high posting frequency".to_string(),
                        evidence: format!("{:.2} notes/hour", notes_per_hour),
                    });
                }
            }
        }
    }

    // Check follower/following ratio
    if let (Some(followers), Some(following)) = (user.followers_count, user.following_count) {
        if following > 100 && followers < 5 {
            indicators.push(SpamIndicator {
                indicator_type: "SUSPICIOUS_RATIO".to_string(),
                severity: Severity::Medium,
                description: "Low follower-to-following ratio".to_string(),
                evidence: format!("Followers: {}, Following: {}", followers, following),
            });
        }
    }

    // Check for empty profile
    if user.description.is_none() || user.description.as_ref().map(|d| d.is_empty()).unwrap_or(true) {
        if user.avatar_url.is_none() {
            indicators.push(SpamIndicator {
                indicator_type: "EMPTY_PROFILE".to_string(),
                severity: Severity::Low,
                description: "Profile has no description and no avatar".to_string(),
                evidence: "Missing profile customization".to_string(),
            });
        }
    }

    print_indicators(&indicators, verbose);
    Ok(indicators)
}

async fn analyze_note(
    client: &Client,
    base_url: &str,
    token: Option<&str>,
    note_id: &str,
    verbose: bool,
) -> Result<Vec<SpamIndicator>, AppError> {
    println!("\n{} {}", "Analyzing note:".blue().bold(), note_id);

    let request = ApiRequest {
        i: token.map(String::from),
        note_id: Some(note_id.to_string()),
        user_id: None,
        limit: None,
    };

    let response = client
        .post(format!("{}/api/notes/show", base_url))
        .json(&request)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(AppError::NoteNotFound(note_id.to_string()));
    }

    let note: Note = response.json().await?;
    let mut indicators = Vec::new();

    if let Some(text) = &note.text {
        // Check for excessive URLs
        let url_count = text.matches("http").count();
        if url_count > 3 {
            indicators.push(SpamIndicator {
                indicator_type: "EXCESSIVE_URLS".to_string(),
                severity: Severity::Medium,
                description: "Note contains many URLs".to_string(),
                evidence: format!("{} URLs detected", url_count),
            });
        }

        // Check for repetitive patterns
        let words: Vec<&str> = text.split_whitespace().collect();
        let mut word_counts: HashMap<&str, u32> = HashMap::new();
        for word in &words {
            *word_counts.entry(word).or_insert(0) += 1;
        }
        let max_repetition = word_counts.values().max().copied().unwrap_or(0);
        if max_repetition > 5 && words.len() > 10 {
            indicators.push(SpamIndicator {
                indicator_type: "REPETITIVE_CONTENT".to_string(),
                severity: Severity::Medium,
                description: "Note contains repetitive words".to_string(),
                evidence: format!("Max word repetition: {}", max_repetition),
            });
        }

        // Check for spam keywords
        let spam_keywords = ["free", "winner", "click here", "act now", "limited time"];
        let lower_text = text.to_lowercase();
        for keyword in spam_keywords {
            if lower_text.contains(keyword) {
                indicators.push(SpamIndicator {
                    indicator_type: "SPAM_KEYWORD".to_string(),
                    severity: Severity::Low,
                    description: "Note contains potential spam keyword".to_string(),
                    evidence: format!("Keyword: '{}'", keyword),
                });
            }
        }
    }

    print_indicators(&indicators, verbose);
    Ok(indicators)
}

async fn analyze_timeline(
    client: &Client,
    base_url: &str,
    token: Option<&str>,
    limit: u32,
    verbose: bool,
) -> Result<(), AppError> {
    println!("\n{}", "Analyzing timeline...".blue().bold());

    let pb = ProgressBar::new(limit as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} notes")
            .unwrap()
            .progress_chars("#>-"),
    );

    #[derive(Serialize)]
    struct TimelineRequest {
        #[serde(skip_serializing_if = "Option::is_none")]
        i: Option<String>,
        limit: u32,
    }

    let request = TimelineRequest {
        i: token.map(String::from),
        limit,
    };

    let response = client
        .post(format!("{}/api/notes/local-timeline", base_url))
        .json(&request)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(AppError::ApiError("Failed to fetch timeline".to_string()));
    }

    let notes: Vec<Note> = response.json().await?;
    let mut user_post_counts: HashMap<String, u32> = HashMap::new();
    let mut suspicious_users: Vec<String> = Vec::new();

    for note in &notes {
        *user_post_counts.entry(note.user_id.clone()).or_insert(0) += 1;
        pb.inc(1);
    }

    pb.finish_with_message("Analysis complete");

    // Find users with high post frequency in the sample
    for (user_id, count) in &user_post_counts {
        if *count > (limit / 10).max(3) {
            suspicious_users.push(user_id.clone());
            println!(
                "  {} User {} has {} notes in sample ({:.1}%)",
                "!".red().bold(),
                user_id,
                count,
                (*count as f64 / notes.len() as f64) * 100.0
            );
        }
    }

    if suspicious_users.is_empty() {
        println!("{}", "  No obvious spam patterns detected in timeline".green());
    } else {
        println!(
            "\n{} {} suspicious user(s) detected",
            "Found".yellow().bold(),
            suspicious_users.len()
        );
    }

    if verbose {
        println!("\n{}", "Timeline statistics:".blue());
        println!("  Total notes analyzed: {}", notes.len());
        println!("  Unique users: {}", user_post_counts.len());
    }

    Ok(())
}

pub async fn analyze_accounts(
    instance: &str,
    token: &str,
    hours: u32,
    min_accounts: u32,
    verbose: bool,
) -> Result<(), AppError> {
    let client = create_client()?;
    let base_url = instance.trim_end_matches('/');

    println!("{}", "Analyzing account creation patterns...".cyan().bold());
    println!("  Time window: {} hours", hours);
    println!("  Threshold: {} accounts", min_accounts);

    #[derive(Serialize)]
    struct UsersRequest {
        i: String,
        limit: u32,
        sort: String,
        state: String,
    }

    let request = UsersRequest {
        i: token.to_string(),
        limit: 100,
        sort: "-createdAt".to_string(),
        state: "all".to_string(),
    };

    // Try the standard endpoint first, then fall back to alternative
    let response = client
        .post(format!("{}/api/admin/show-users", base_url))
        .json(&request)
        .send()
        .await?;

    if response.status() == reqwest::StatusCode::FORBIDDEN {
        return Err(AppError::AuthenticationFailed);
    }

    if !response.status().is_success() {
        return Err(AppError::ApiError(format!(
            "Failed to fetch users: {}",
            response.status()
        )));
    }

    let users: Vec<User> = response.json().await?;
    let cutoff = Utc::now() - chrono::Duration::hours(hours as i64);
    let mut recent_accounts = 0;

    for user in &users {
        if let Some(created_at) = &user.created_at {
            if let Ok(created) = DateTime::parse_from_rfc3339(created_at) {
                if created.with_timezone(&Utc) > cutoff {
                    recent_accounts += 1;
                    if verbose {
                        println!(
                            "  {} @{} created at {}",
                            "+".green(),
                            user.username,
                            created_at
                        );
                    }
                }
            }
        }
    }

    println!("\n{}", "Results:".blue().bold());
    println!(
        "  Accounts created in last {} hours: {}",
        hours, recent_accounts
    );

    if recent_accounts >= min_accounts {
        println!(
            "  {} High account creation rate detected!",
            "WARNING:".red().bold()
        );
    } else {
        println!("  {} Account creation rate is normal", "OK:".green().bold());
    }

    Ok(())
}

fn print_indicators(indicators: &[SpamIndicator], verbose: bool) {
    if indicators.is_empty() {
        println!("  {} No spam indicators detected", "OK".green().bold());
        return;
    }

    println!("\n  {} {} indicator(s) found:", "Found".yellow().bold(), indicators.len());
    for indicator in indicators {
        println!(
            "    [{}] {}: {}",
            indicator.severity,
            indicator.indicator_type.bold(),
            indicator.description
        );
        if verbose {
            println!("      Evidence: {}", indicator.evidence.dimmed());
        }
    }
}
