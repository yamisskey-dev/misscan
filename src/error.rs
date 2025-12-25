use thiserror::Error;

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum AppError {
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("JSON parsing failed: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Missing instance URL. Use --instance or -i to specify")]
    MissingInstance,

    #[error("Missing API token. Use --token or -t to specify")]
    MissingToken,

    #[error("Invalid instance URL: {0}")]
    InvalidUrl(String),

    #[error("API error: {0}")]
    ApiError(String),

    #[error("Rate limited by instance")]
    RateLimited,

    #[error("Instance not reachable: {0}")]
    InstanceUnreachable(String),

    #[error("Authentication failed")]
    AuthenticationFailed,

    #[error("User not found: {0}")]
    UserNotFound(String),

    #[error("Note not found: {0}")]
    NoteNotFound(String),
}
