use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Settings {
    pub permissions: Permissions,
}

#[derive(Debug, Deserialize)]
pub struct Permissions {
    pub deny: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("settings file not found: {0}")]
    NotFound(String),
    #[error("failed to read settings file: {0}")]
    ReadError(#[from] std::io::Error),
    #[error("failed to parse settings JSON: {0}")]
    ParseError(#[from] serde_json::Error),
}

pub fn load_settings(dir: &Path) -> Result<Settings, ConfigError> {
    let path = dir.join(".claude").join("settings.json");
    if !path.exists() {
        return Err(ConfigError::NotFound(path.display().to_string()));
    }
    let content = std::fs::read_to_string(&path)?;
    let settings: Settings = serde_json::from_str(&content)?;
    Ok(settings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_load_valid_settings() {
        let dir = tempfile::tempdir().unwrap();
        let claude_dir = dir.path().join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();
        fs::write(
            claude_dir.join("settings.json"),
            r#"{"permissions":{"deny":["Read(./a.txt)","Read(./.env)"]}}"#,
        )
        .unwrap();

        let settings = load_settings(dir.path()).unwrap();
        assert_eq!(settings.permissions.deny.len(), 2);
        assert_eq!(settings.permissions.deny[0], "Read(./a.txt)");
    }

    #[test]
    fn test_load_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let result = load_settings(dir.path());
        assert!(matches!(result, Err(ConfigError::NotFound(_))));
    }

    #[test]
    fn test_load_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let claude_dir = dir.path().join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();
        fs::write(claude_dir.join("settings.json"), "not json").unwrap();

        let result = load_settings(dir.path());
        assert!(matches!(result, Err(ConfigError::ParseError(_))));
    }
}
