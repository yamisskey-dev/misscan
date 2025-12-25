use clap::{Parser, Subcommand};
use colored::Colorize;
use std::process::ExitCode;

mod detect;
mod error;
mod scanner;
mod monitor;

use error::AppError;

#[derive(Parser)]
#[command(name = "misscan")]
#[command(author = "hitalin")]
#[command(version = "0.1.0")]
#[command(about = "Anti-spam and penetration testing toolkit for Misskey", long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    /// Target Misskey instance URL
    #[arg(short, long, global = true)]
    instance: Option<String>,

    /// API token for authenticated operations
    #[arg(short, long, global = true)]
    token: Option<String>,

    /// Enable verbose output
    #[arg(short, long, global = true, default_value = "false")]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan instance for security vulnerabilities
    #[command(visible_alias = "s")]
    Scan {
        /// Target instance URL
        #[arg(short, long)]
        target: String,

        /// Check for open registration
        #[arg(long, default_value = "true")]
        check_registration: bool,

        /// Check API rate limits
        #[arg(long, default_value = "true")]
        check_rate_limit: bool,

        /// Check for known vulnerable endpoints
        #[arg(long, default_value = "true")]
        check_endpoints: bool,
    },

    /// Detect spam patterns in notes/users
    #[command(visible_alias = "d")]
    Detect {
        /// User ID to analyze
        #[arg(short, long)]
        user_id: Option<String>,

        /// Note ID to analyze
        #[arg(short, long)]
        note_id: Option<String>,

        /// Analyze recent timeline for spam patterns
        #[arg(long)]
        timeline: bool,

        /// Number of notes to analyze
        #[arg(short, long, default_value = "100")]
        limit: u32,
    },

    /// Monitor instance for real-time spam detection
    #[command(visible_alias = "m")]
    Monitor {
        /// Polling interval in seconds
        #[arg(short, long, default_value = "5")]
        interval: u64,

        /// Alert threshold for suspicious activity
        #[arg(short, long, default_value = "10")]
        threshold: u32,

        /// Output format (text, json)
        #[arg(short, long, default_value = "text")]
        format: String,
    },

    /// Analyze account creation patterns
    #[command(visible_alias = "a")]
    Analyze {
        /// Time window in hours to analyze
        #[arg(short, long, default_value = "24")]
        hours: u32,

        /// Minimum accounts to flag as suspicious
        #[arg(short, long, default_value = "5")]
        min_accounts: u32,
    },

    /// Generate security report for an instance
    #[command(visible_alias = "r")]
    Report {
        /// Target instance URL
        #[arg(short, long)]
        target: String,

        /// Output file path
        #[arg(short, long)]
        output: Option<String>,

        /// Report format (text, json, markdown)
        #[arg(short, long, default_value = "markdown")]
        format: String,
    },
}

fn print_banner() {
    let banner = r#"
    __  ____
   /  |/  (_)______________ _____ ___
  / /|_/ / / ___/ ___/ ___/ __  / __ \
 / /  / / (__  |__  ) /__/ /_/ / / / /
/_/  /_/_/____/____/\___/\__,_/_/ /_/

    Anti-spam & Security Toolkit for Misskey
"#;
    println!("{}", banner.cyan());
}

#[tokio::main]
async fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    print_banner();

    let cli = Cli::parse();

    let result = run(cli).await;

    match result {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{} {}", "Error:".red().bold(), e);
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<(), AppError> {
    match cli.command {
        Commands::Scan {
            target,
            check_registration,
            check_rate_limit,
            check_endpoints,
        } => {
            scanner::scan_instance(
                &target,
                check_registration,
                check_rate_limit,
                check_endpoints,
                cli.verbose,
            )
            .await
        }
        Commands::Detect {
            user_id,
            note_id,
            timeline,
            limit,
        } => {
            let instance = cli.instance.ok_or(AppError::MissingInstance)?;
            let token = cli.token;
            detect::detect_spam(&instance, token.as_deref(), user_id, note_id, timeline, limit, cli.verbose).await
        }
        Commands::Monitor {
            interval,
            threshold,
            format,
        } => {
            let instance = cli.instance.ok_or(AppError::MissingInstance)?;
            let token = cli.token;
            monitor::start_monitoring(&instance, token.as_deref(), interval, threshold, &format, cli.verbose).await
        }
        Commands::Analyze { hours, min_accounts } => {
            let instance = cli.instance.ok_or(AppError::MissingInstance)?;
            let token = cli.token.ok_or(AppError::MissingToken)?;
            detect::analyze_accounts(&instance, &token, hours, min_accounts, cli.verbose).await
        }
        Commands::Report {
            target,
            output,
            format,
        } => {
            scanner::generate_report(&target, output.as_deref(), &format, cli.verbose).await
        }
    }
}
