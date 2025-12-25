use crate::error::AppError;
use chrono::Utc;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct SecurityFinding {
    pub category: String,
    pub severity: FindingSeverity,
    pub title: String,
    pub description: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for FindingSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingSeverity::Info => write!(f, "{}", "INFO".blue()),
            FindingSeverity::Low => write!(f, "{}", "LOW".yellow()),
            FindingSeverity::Medium => write!(f, "{}", "MEDIUM".truecolor(255, 165, 0)),
            FindingSeverity::High => write!(f, "{}", "HIGH".red()),
            FindingSeverity::Critical => write!(f, "{}", "CRITICAL".red().bold()),
        }
    }
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct InstanceMeta {
    #[serde(rename = "maintainerName")]
    maintainer_name: Option<String>,
    #[serde(rename = "maintainerEmail")]
    maintainer_email: Option<String>,
    version: Option<String>,
    name: Option<String>,
    uri: Option<String>,
    #[serde(rename = "disableRegistration")]
    disable_registration: Option<bool>,
    #[serde(rename = "emailRequiredForSignup")]
    email_required: Option<bool>,
    #[serde(rename = "enableHcaptcha")]
    hcaptcha_enabled: Option<bool>,
    #[serde(rename = "enableRecaptcha")]
    recaptcha_enabled: Option<bool>,
    #[serde(rename = "enableTurnstile")]
    turnstile_enabled: Option<bool>,
}

fn create_client() -> Result<Client, AppError> {
    Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("misscan/0.1.0")
        .build()
        .map_err(AppError::HttpError)
}

pub async fn scan_instance(
    target: &str,
    check_registration: bool,
    check_rate_limit: bool,
    check_endpoints: bool,
    verbose: bool,
) -> Result<(), AppError> {
    let client = create_client()?;
    let base_url = target.trim_end_matches('/');

    println!("{} {}", "Scanning instance:".cyan().bold(), target);
    println!();

    let pb = ProgressBar::new(4);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] {msg}")
            .unwrap(),
    );

    let mut findings: Vec<SecurityFinding> = Vec::new();

    // 1. Check instance reachability and get metadata
    pb.set_message("Checking instance metadata...");
    match fetch_instance_meta(&client, base_url).await {
        Ok(meta) => {
            if verbose {
                println!("  Instance: {}", meta.name.as_deref().unwrap_or("Unknown"));
                println!("  Version: {}", meta.version.as_deref().unwrap_or("Unknown"));
            }

            // Check registration settings
            if check_registration {
                if meta.disable_registration != Some(true) {
                    let has_captcha = meta.hcaptcha_enabled == Some(true)
                        || meta.recaptcha_enabled == Some(true)
                        || meta.turnstile_enabled == Some(true);

                    if !has_captcha {
                        findings.push(SecurityFinding {
                            category: "Registration".to_string(),
                            severity: FindingSeverity::High,
                            title: "Open registration without CAPTCHA".to_string(),
                            description: "Instance allows registration without any CAPTCHA protection".to_string(),
                            recommendation: "Enable hCaptcha, reCAPTCHA, or Turnstile to prevent automated account creation".to_string(),
                        });
                    } else {
                        findings.push(SecurityFinding {
                            category: "Registration".to_string(),
                            severity: FindingSeverity::Info,
                            title: "Registration with CAPTCHA enabled".to_string(),
                            description: "Instance has CAPTCHA protection for registration".to_string(),
                            recommendation: "No action needed".to_string(),
                        });
                    }

                    if meta.email_required != Some(true) {
                        findings.push(SecurityFinding {
                            category: "Registration".to_string(),
                            severity: FindingSeverity::Medium,
                            title: "Email not required for signup".to_string(),
                            description: "Users can register without email verification".to_string(),
                            recommendation: "Consider requiring email verification to reduce spam accounts".to_string(),
                        });
                    }
                } else {
                    findings.push(SecurityFinding {
                        category: "Registration".to_string(),
                        severity: FindingSeverity::Info,
                        title: "Registration is disabled".to_string(),
                        description: "Instance does not allow new registrations".to_string(),
                        recommendation: "No action needed".to_string(),
                    });
                }
            }
        }
        Err(e) => {
            return Err(AppError::InstanceUnreachable(e.to_string()));
        }
    }
    pb.inc(1);

    // 2. Check rate limiting
    if check_rate_limit {
        pb.set_message("Testing rate limits...");
        let rate_limit_result = test_rate_limits(&client, base_url).await;
        match rate_limit_result {
            RateLimitResult::NoLimit => {
                findings.push(SecurityFinding {
                    category: "Rate Limiting".to_string(),
                    severity: FindingSeverity::High,
                    title: "No rate limiting detected".to_string(),
                    description: "API endpoints do not appear to be rate limited".to_string(),
                    recommendation: "Implement rate limiting to prevent abuse".to_string(),
                });
            }
            RateLimitResult::Limited { requests_per_minute } => {
                findings.push(SecurityFinding {
                    category: "Rate Limiting".to_string(),
                    severity: FindingSeverity::Info,
                    title: "Rate limiting detected".to_string(),
                    description: format!(
                        "API appears to allow ~{} requests per minute",
                        requests_per_minute
                    ),
                    recommendation: "No action needed".to_string(),
                });
            }
            RateLimitResult::Error(e) => {
                if verbose {
                    println!("  {} Rate limit test failed: {}", "!".yellow(), e);
                }
            }
        }
    }
    pb.inc(1);

    // 3. Check for known vulnerable endpoints
    if check_endpoints {
        pb.set_message("Checking API endpoints...");
        let endpoint_findings = check_api_endpoints(&client, base_url, verbose).await;
        findings.extend(endpoint_findings);
    }
    pb.inc(1);

    // 4. Check for information disclosure
    pb.set_message("Checking for information disclosure...");
    let info_findings = check_info_disclosure(&client, base_url, verbose).await;
    findings.extend(info_findings);
    pb.inc(1);

    pb.finish_with_message("Scan complete");
    println!();

    // Print findings
    print_findings(&findings);

    Ok(())
}

async fn fetch_instance_meta(client: &Client, base_url: &str) -> Result<InstanceMeta, AppError> {
    let response = client
        .post(format!("{}/api/meta", base_url))
        .json(&serde_json::json!({"detail": true}))
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(AppError::ApiError(format!(
            "Failed to fetch instance metadata: {}",
            response.status()
        )));
    }

    let meta: InstanceMeta = response.json().await?;
    Ok(meta)
}

enum RateLimitResult {
    NoLimit,
    Limited { requests_per_minute: u32 },
    Error(String),
}

async fn test_rate_limits(client: &Client, base_url: &str) -> RateLimitResult {
    let test_requests = 10;
    let mut success_count = 0;

    for _ in 0..test_requests {
        let result = client
            .post(format!("{}/api/meta", base_url))
            .json(&serde_json::json!({}))
            .send()
            .await;

        match result {
            Ok(response) => {
                if response.status().is_success() {
                    success_count += 1;
                } else if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
                    return RateLimitResult::Limited {
                        requests_per_minute: (success_count * 6) as u32,
                    };
                }
            }
            Err(e) => {
                return RateLimitResult::Error(e.to_string());
            }
        }
    }

    if success_count == test_requests {
        RateLimitResult::NoLimit
    } else {
        RateLimitResult::Limited {
            requests_per_minute: (success_count * 6) as u32,
        }
    }
}

async fn check_api_endpoints(
    client: &Client,
    base_url: &str,
    verbose: bool,
) -> Vec<SecurityFinding> {
    let mut findings = Vec::new();

    // Check for unauthenticated access to sensitive endpoints
    let sensitive_endpoints = [
        ("admin/meta", "Admin metadata"),
        ("admin/server-info", "Server information"),
        ("federation/instances", "Federation instances list"),
    ];

    for (endpoint, description) in sensitive_endpoints {
        let result = client
            .post(format!("{}/api/{}", base_url, endpoint))
            .json(&serde_json::json!({}))
            .send()
            .await;

        if let Ok(response) = result {
            if response.status().is_success() {
                findings.push(SecurityFinding {
                    category: "API Security".to_string(),
                    severity: FindingSeverity::Medium,
                    title: format!("Unauthenticated access to {}", endpoint),
                    description: format!(
                        "{} is accessible without authentication",
                        description
                    ),
                    recommendation: "Consider restricting access to authenticated users".to_string(),
                });
            } else if verbose {
                println!(
                    "  {} {} requires authentication",
                    "OK".green(),
                    endpoint
                );
            }
        }
    }

    findings
}

async fn check_info_disclosure(
    client: &Client,
    base_url: &str,
    _verbose: bool,
) -> Vec<SecurityFinding> {
    let mut findings = Vec::new();

    // Check for exposed .well-known endpoints
    let well_known_paths = [
        ".well-known/nodeinfo",
        ".well-known/host-meta",
    ];

    for path in well_known_paths {
        let result = client
            .get(format!("{}/{}", base_url, path))
            .send()
            .await;

        if let Ok(response) = result {
            if response.status().is_success() {
                findings.push(SecurityFinding {
                    category: "Information Disclosure".to_string(),
                    severity: FindingSeverity::Info,
                    title: format!("{} is accessible", path),
                    description: "This is standard for ActivityPub federation".to_string(),
                    recommendation: "No action needed - required for federation".to_string(),
                });
            }
        }
    }

    findings
}

fn print_findings(findings: &[SecurityFinding]) {
    if findings.is_empty() {
        println!("{}", "No security issues found.".green().bold());
        return;
    }

    let critical = findings
        .iter()
        .filter(|f| f.severity == FindingSeverity::Critical)
        .count();
    let high = findings
        .iter()
        .filter(|f| f.severity == FindingSeverity::High)
        .count();
    let medium = findings
        .iter()
        .filter(|f| f.severity == FindingSeverity::Medium)
        .count();
    let low = findings
        .iter()
        .filter(|f| f.severity == FindingSeverity::Low)
        .count();
    let info = findings
        .iter()
        .filter(|f| f.severity == FindingSeverity::Info)
        .count();

    println!(
        "{} {} finding(s): {} critical, {} high, {} medium, {} low, {} info",
        "Summary:".bold(),
        findings.len(),
        critical,
        high,
        medium,
        low,
        info
    );
    println!();

    for finding in findings {
        println!(
            "[{}] {} - {}",
            finding.severity,
            finding.category.bold(),
            finding.title
        );
        println!("  {}", finding.description.dimmed());
        println!("  {} {}", "Recommendation:".blue(), finding.recommendation);
        println!();
    }
}

pub async fn generate_report(
    target: &str,
    output: Option<&str>,
    format: &str,
    verbose: bool,
) -> Result<(), AppError> {
    let client = create_client()?;
    let base_url = target.trim_end_matches('/');

    println!(
        "{} {}",
        "Generating security report for:".cyan().bold(),
        target
    );

    let mut findings: Vec<SecurityFinding> = Vec::new();

    // Gather all findings
    if let Ok(meta) = fetch_instance_meta(&client, base_url).await {
        // Registration checks
        if meta.disable_registration != Some(true) {
            let has_captcha = meta.hcaptcha_enabled == Some(true)
                || meta.recaptcha_enabled == Some(true)
                || meta.turnstile_enabled == Some(true);

            if !has_captcha {
                findings.push(SecurityFinding {
                    category: "Registration".to_string(),
                    severity: FindingSeverity::High,
                    title: "Open registration without CAPTCHA".to_string(),
                    description: "Instance allows registration without any CAPTCHA protection"
                        .to_string(),
                    recommendation:
                        "Enable hCaptcha, reCAPTCHA, or Turnstile to prevent automated account creation"
                            .to_string(),
                });
            }

            if meta.email_required != Some(true) {
                findings.push(SecurityFinding {
                    category: "Registration".to_string(),
                    severity: FindingSeverity::Medium,
                    title: "Email not required for signup".to_string(),
                    description: "Users can register without email verification".to_string(),
                    recommendation:
                        "Consider requiring email verification to reduce spam accounts".to_string(),
                });
            }
        }
    }

    // Rate limit check
    match test_rate_limits(&client, base_url).await {
        RateLimitResult::NoLimit => {
            findings.push(SecurityFinding {
                category: "Rate Limiting".to_string(),
                severity: FindingSeverity::High,
                title: "No rate limiting detected".to_string(),
                description: "API endpoints do not appear to be rate limited".to_string(),
                recommendation: "Implement rate limiting to prevent abuse".to_string(),
            });
        }
        _ => {}
    }

    // API endpoint checks
    findings.extend(check_api_endpoints(&client, base_url, verbose).await);

    // Generate report
    let report = match format {
        "json" => generate_json_report(target, &findings)?,
        "markdown" | "md" => generate_markdown_report(target, &findings),
        _ => generate_text_report(target, &findings),
    };

    if let Some(output_path) = output {
        std::fs::write(output_path, &report)?;
        println!("{} {}", "Report saved to:".green().bold(), output_path);
    } else {
        println!("\n{}", report);
    }

    Ok(())
}

fn generate_text_report(target: &str, findings: &[SecurityFinding]) -> String {
    let mut report = String::new();
    report.push_str(&format!(
        "Security Report for {}\n",
        target
    ));
    report.push_str(&format!("Generated: {}\n", Utc::now().format("%Y-%m-%d %H:%M:%S UTC")));
    report.push_str(&"=".repeat(60));
    report.push('\n');
    report.push('\n');

    for finding in findings {
        report.push_str(&format!(
            "[{:?}] {} - {}\n",
            finding.severity, finding.category, finding.title
        ));
        report.push_str(&format!("  {}\n", finding.description));
        report.push_str(&format!("  Recommendation: {}\n", finding.recommendation));
        report.push('\n');
    }

    report
}

fn generate_markdown_report(target: &str, findings: &[SecurityFinding]) -> String {
    let mut report = String::new();
    report.push_str(&format!("# Security Report for {}\n\n", target));
    report.push_str(&format!(
        "**Generated:** {}\n\n",
        Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    ));

    report.push_str("## Summary\n\n");
    report.push_str(&format!("Total findings: {}\n\n", findings.len()));

    report.push_str("## Findings\n\n");
    for finding in findings {
        report.push_str(&format!(
            "### [{:?}] {}\n\n",
            finding.severity, finding.title
        ));
        report.push_str(&format!("**Category:** {}\n\n", finding.category));
        report.push_str(&format!("{}\n\n", finding.description));
        report.push_str(&format!(
            "**Recommendation:** {}\n\n",
            finding.recommendation
        ));
        report.push_str("---\n\n");
    }

    report
}

#[derive(Serialize)]
struct JsonReport {
    target: String,
    generated_at: String,
    findings: Vec<JsonFinding>,
}

#[derive(Serialize)]
struct JsonFinding {
    category: String,
    severity: String,
    title: String,
    description: String,
    recommendation: String,
}

fn generate_json_report(target: &str, findings: &[SecurityFinding]) -> Result<String, AppError> {
    let report = JsonReport {
        target: target.to_string(),
        generated_at: Utc::now().to_rfc3339(),
        findings: findings
            .iter()
            .map(|f| JsonFinding {
                category: f.category.clone(),
                severity: format!("{:?}", f.severity),
                title: f.title.clone(),
                description: f.description.clone(),
                recommendation: f.recommendation.clone(),
            })
            .collect(),
    };

    serde_json::to_string_pretty(&report).map_err(AppError::JsonError)
}
