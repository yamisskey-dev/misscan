use crate::error::AppError;
use chrono::{DateTime, Utc};
use colored::Colorize;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::interval;

#[derive(Debug, Deserialize, Clone)]
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
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
struct User {
    id: String,
    username: String,
    #[serde(default)]
    host: Option<String>,
    #[serde(rename = "createdAt")]
    created_at: Option<String>,
}

#[derive(Debug, Serialize)]
struct Alert {
    timestamp: String,
    alert_type: String,
    severity: String,
    user_id: String,
    username: String,
    details: String,
}

fn create_client() -> Result<Client, AppError> {
    Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("misscan/0.1.0")
        .build()
        .map_err(AppError::HttpError)
}

pub async fn start_monitoring(
    instance: &str,
    token: Option<&str>,
    poll_interval: u64,
    threshold: u32,
    format: &str,
    verbose: bool,
) -> Result<(), AppError> {
    let client = create_client()?;
    let base_url = instance.trim_end_matches('/');

    println!("{}", "Starting real-time spam monitoring...".cyan().bold());
    println!("  Instance: {}", base_url);
    println!("  Poll interval: {}s", poll_interval);
    println!("  Alert threshold: {} notes/minute", threshold);
    println!();
    println!("{}", "Press Ctrl+C to stop monitoring".dimmed());
    println!();

    let mut interval_timer = interval(Duration::from_secs(poll_interval));
    let mut last_note_id: Option<String> = None;
    let mut user_activity: HashMap<String, Vec<DateTime<Utc>>> = HashMap::new();

    loop {
        interval_timer.tick().await;

        match fetch_recent_notes(&client, base_url, token, last_note_id.as_deref()).await {
            Ok(notes) => {
                if !notes.is_empty() {
                    last_note_id = Some(notes[0].id.clone());

                    for note in &notes {
                        // Track user activity
                        if let Ok(created) = DateTime::parse_from_rfc3339(&note.created_at) {
                            let created_utc = created.with_timezone(&Utc);
                            let activity = user_activity
                                .entry(note.user_id.clone())
                                .or_insert_with(Vec::new);
                            activity.push(created_utc);

                            // Clean old entries (older than 1 minute)
                            let one_minute_ago = Utc::now() - chrono::Duration::minutes(1);
                            activity.retain(|t| *t > one_minute_ago);

                            // Check threshold
                            if activity.len() as u32 >= threshold {
                                let username = note
                                    .user
                                    .as_ref()
                                    .map(|u| u.username.as_str())
                                    .unwrap_or("unknown");

                                let alert = Alert {
                                    timestamp: Utc::now().to_rfc3339(),
                                    alert_type: "HIGH_FREQUENCY".to_string(),
                                    severity: "HIGH".to_string(),
                                    user_id: note.user_id.clone(),
                                    username: username.to_string(),
                                    details: format!(
                                        "{} notes in the last minute",
                                        activity.len()
                                    ),
                                };

                                print_alert(&alert, format);

                                // Reset counter after alert
                                activity.clear();
                            }
                        }

                        // Check for spam patterns in content
                        if let Some(text) = &note.text {
                            check_content_patterns(
                                text,
                                &note.user_id,
                                note.user.as_ref().map(|u| u.username.as_str()).unwrap_or("unknown"),
                                format,
                            );
                        }
                    }

                    if verbose {
                        println!(
                            "  {} Processed {} new note(s)",
                            "+".green(),
                            notes.len()
                        );
                    }
                }
            }
            Err(e) => {
                eprintln!("{} Failed to fetch notes: {}", "!".red(), e);
            }
        }

        // Check for new account spam
        if let Some(token_str) = token {
            if let Ok(new_users) = check_new_accounts(&client, base_url, token_str).await {
                if new_users >= threshold {
                    let alert = Alert {
                        timestamp: Utc::now().to_rfc3339(),
                        alert_type: "MASS_REGISTRATION".to_string(),
                        severity: "CRITICAL".to_string(),
                        user_id: String::new(),
                        username: String::new(),
                        details: format!(
                            "{} new accounts in the last minute",
                            new_users
                        ),
                    };
                    print_alert(&alert, format);
                }
            }
        }
    }
}

async fn fetch_recent_notes(
    client: &Client,
    base_url: &str,
    token: Option<&str>,
    since_id: Option<&str>,
) -> Result<Vec<Note>, AppError> {
    #[derive(Serialize)]
    struct TimelineRequest {
        #[serde(skip_serializing_if = "Option::is_none")]
        i: Option<String>,
        limit: u32,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "sinceId")]
        since_id: Option<String>,
    }

    let request = TimelineRequest {
        i: token.map(String::from),
        limit: 50,
        since_id: since_id.map(String::from),
    };

    let response = client
        .post(format!("{}/api/notes/local-timeline", base_url))
        .json(&request)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(AppError::ApiError(format!(
            "Failed to fetch timeline: {}",
            response.status()
        )));
    }

    let notes: Vec<Note> = response.json().await?;
    Ok(notes)
}

async fn check_new_accounts(
    client: &Client,
    base_url: &str,
    token: &str,
) -> Result<u32, AppError> {
    #[derive(Serialize)]
    struct UsersRequest {
        i: String,
        limit: u32,
        sort: String,
        state: String,
    }

    let request = UsersRequest {
        i: token.to_string(),
        limit: 50,
        sort: "-createdAt".to_string(),
        state: "all".to_string(),
    };

    let response = client
        .post(format!("{}/api/admin/show-users", base_url))
        .json(&request)
        .send()
        .await?;

    if !response.status().is_success() {
        return Ok(0);
    }

    #[derive(Deserialize)]
    struct UserInfo {
        #[serde(rename = "createdAt")]
        created_at: Option<String>,
    }

    let users: Vec<UserInfo> = response.json().await.unwrap_or_default();
    let one_minute_ago = Utc::now() - chrono::Duration::minutes(1);
    let new_count = users
        .iter()
        .filter(|u| {
            u.created_at
                .as_ref()
                .and_then(|c| DateTime::parse_from_rfc3339(c).ok())
                .map(|c| c.with_timezone(&Utc) > one_minute_ago)
                .unwrap_or(false)
        })
        .count() as u32;

    Ok(new_count)
}

fn check_content_patterns(text: &str, user_id: &str, username: &str, format: &str) {
    let text_lower = text.to_lowercase();

    // Check for excessive URLs
    let url_count = text.matches("http").count();
    if url_count > 5 {
        let alert = Alert {
            timestamp: Utc::now().to_rfc3339(),
            alert_type: "EXCESSIVE_URLS".to_string(),
            severity: "MEDIUM".to_string(),
            user_id: user_id.to_string(),
            username: username.to_string(),
            details: format!("{} URLs in single note", url_count),
        };
        print_alert(&alert, format);
    }

    // Check for spam keywords
    let spam_indicators = [
        "free money",
        "click here now",
        "limited offer",
        "act fast",
        "wire transfer",
        "cryptocurrency giveaway",
    ];

    for indicator in spam_indicators {
        if text_lower.contains(indicator) {
            let alert = Alert {
                timestamp: Utc::now().to_rfc3339(),
                alert_type: "SPAM_CONTENT".to_string(),
                severity: "HIGH".to_string(),
                user_id: user_id.to_string(),
                username: username.to_string(),
                details: format!("Contains spam indicator: '{}'", indicator),
            };
            print_alert(&alert, format);
            break;
        }
    }

    // Check for repetitive content
    let words: Vec<&str> = text.split_whitespace().collect();
    if words.len() > 10 {
        let mut word_counts: HashMap<&str, u32> = HashMap::new();
        for word in &words {
            *word_counts.entry(word).or_insert(0) += 1;
        }
        let max_rep = word_counts.values().max().copied().unwrap_or(0);
        if max_rep > 5 {
            let alert = Alert {
                timestamp: Utc::now().to_rfc3339(),
                alert_type: "REPETITIVE_CONTENT".to_string(),
                severity: "LOW".to_string(),
                user_id: user_id.to_string(),
                username: username.to_string(),
                details: format!("Word repeated {} times", max_rep),
            };
            print_alert(&alert, format);
        }
    }
}

fn print_alert(alert: &Alert, format: &str) {
    match format {
        "json" => {
            if let Ok(json) = serde_json::to_string(alert) {
                println!("{}", json);
            }
        }
        _ => {
            let severity_colored = match alert.severity.as_str() {
                "CRITICAL" => alert.severity.red().bold().to_string(),
                "HIGH" => alert.severity.red().to_string(),
                "MEDIUM" => alert.severity.yellow().to_string(),
                _ => alert.severity.blue().to_string(),
            };

            println!(
                "{} [{}] {} @{}: {}",
                "ALERT".red().bold(),
                severity_colored,
                alert.alert_type.bold(),
                alert.username,
                alert.details
            );
        }
    }
}
