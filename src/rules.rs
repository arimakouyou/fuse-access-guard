use std::path::{Path, PathBuf};

use glob::Pattern;

use crate::config::Settings;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Read,
    Write,
    Execute,
}

#[derive(Debug)]
pub enum PathPattern {
    Exact(PathBuf),
    Glob(Pattern, glob::MatchOptions),
}

#[derive(Debug)]
pub struct DenyRule {
    pub operation: Operation,
    pub pattern: PathPattern,
}

#[derive(Debug, thiserror::Error)]
pub enum RuleParseError {
    #[error("invalid deny rule format: {0}")]
    InvalidFormat(String),
    #[error("unknown operation: {0}")]
    UnknownOperation(String),
    #[error("invalid glob pattern: {0}")]
    InvalidGlob(#[from] glob::PatternError),
}

#[derive(Debug)]
pub struct AccessRules {
    rules: Vec<DenyRule>,
}

impl AccessRules {
    pub fn from_settings(settings: &Settings, cwd: &Path) -> Result<Self, RuleParseError> {
        let mut rules = Vec::new();
        for entry in &settings.permissions.deny {
            rules.push(parse_deny_rule(entry, cwd)?);
        }
        Ok(AccessRules { rules })
    }

    /// Returns the unique set of paths referenced by deny rules.
    /// For glob patterns, returns the pattern string as a PathBuf.
    pub fn denied_paths(&self) -> Vec<PathBuf> {
        self.rules
            .iter()
            .map(|rule| match &rule.pattern {
                PathPattern::Exact(p) => p.clone(),
                PathPattern::Glob(pattern, _) => PathBuf::from(pattern.as_str()),
            })
            .collect()
    }

    pub fn is_denied(&self, path: &Path, op: Operation) -> bool {
        self.rules.iter().any(|rule| {
            if rule.operation != op {
                return false;
            }
            match &rule.pattern {
                PathPattern::Exact(p) => path == p,
                PathPattern::Glob(pattern, opts) => {
                    pattern.matches_with(&path.to_string_lossy(), *opts)
                }
            }
        })
    }
}

fn parse_deny_rule(entry: &str, cwd: &Path) -> Result<DenyRule, RuleParseError> {
    // Format: "Operation(path)" e.g. "Read(./a.txt)", "Write(./*.env*)"
    let open = entry
        .find('(')
        .ok_or_else(|| RuleParseError::InvalidFormat(entry.to_string()))?;
    let close = entry
        .rfind(')')
        .ok_or_else(|| RuleParseError::InvalidFormat(entry.to_string()))?;

    if close <= open + 1 {
        return Err(RuleParseError::InvalidFormat(entry.to_string()));
    }

    let op_str = &entry[..open];
    let path_str = &entry[open + 1..close];

    let operation = match op_str {
        "Read" => Operation::Read,
        "Write" => Operation::Write,
        "Execute" => Operation::Execute,
        _ => return Err(RuleParseError::UnknownOperation(op_str.to_string())),
    };

    // Resolve relative paths against cwd
    let resolved = if path_str.starts_with("./") || path_str.starts_with("../") {
        // Strip "./" prefix and join with cwd to avoid paths like "/foo/./bar"
        let stripped = path_str.strip_prefix("./").unwrap_or(path_str);
        cwd.join(stripped)
    } else {
        PathBuf::from(path_str)
    };

    let resolved_str = resolved.to_string_lossy();
    let has_glob = resolved_str.contains('*') || resolved_str.contains('?') || resolved_str.contains('[');

    let pattern = if has_glob {
        let match_opts = glob::MatchOptions {
            require_literal_leading_dot: false,
            ..Default::default()
        };
        PathPattern::Glob(Pattern::new(&resolved_str)?, match_opts)
    } else {
        PathPattern::Exact(resolved)
    };

    Ok(DenyRule { operation, pattern })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Permissions, Settings};

    fn make_settings(deny: Vec<&str>) -> Settings {
        Settings {
            permissions: Permissions {
                deny: deny.into_iter().map(String::from).collect(),
            },
        }
    }

    #[test]
    fn test_exact_read_denied() {
        let cwd = Path::new("/home/user/project");
        let settings = make_settings(vec!["Read(./a.txt)"]);
        let rules = AccessRules::from_settings(&settings, cwd).unwrap();

        assert!(rules.is_denied(Path::new("/home/user/project/a.txt"), Operation::Read));
        assert!(!rules.is_denied(Path::new("/home/user/project/b.txt"), Operation::Read));
    }

    #[test]
    fn test_write_not_blocked_by_read_rule() {
        let cwd = Path::new("/home/user/project");
        let settings = make_settings(vec!["Read(./a.txt)"]);
        let rules = AccessRules::from_settings(&settings, cwd).unwrap();

        assert!(!rules.is_denied(Path::new("/home/user/project/a.txt"), Operation::Write));
    }

    #[test]
    fn test_glob_pattern() {
        let cwd = Path::new("/home/user/project");
        let settings = make_settings(vec!["Read(./*.env*)"]);
        let rules = AccessRules::from_settings(&settings, cwd).unwrap();

        assert!(rules.is_denied(Path::new("/home/user/project/.env"), Operation::Read));
        assert!(rules.is_denied(Path::new("/home/user/project/.env.local"), Operation::Read));
        assert!(!rules.is_denied(Path::new("/home/user/project/config.json"), Operation::Read));
    }

    #[test]
    fn test_write_operation() {
        let cwd = Path::new("/home/user/project");
        let settings = make_settings(vec!["Write(./secret.key)"]);
        let rules = AccessRules::from_settings(&settings, cwd).unwrap();

        assert!(rules.is_denied(Path::new("/home/user/project/secret.key"), Operation::Write));
        assert!(!rules.is_denied(Path::new("/home/user/project/secret.key"), Operation::Read));
    }

    #[test]
    fn test_execute_operation() {
        let cwd = Path::new("/home/user/project");
        let settings = make_settings(vec!["Execute(./dangerous.sh)"]);
        let rules = AccessRules::from_settings(&settings, cwd).unwrap();

        assert!(rules.is_denied(
            Path::new("/home/user/project/dangerous.sh"),
            Operation::Execute
        ));
    }

    #[test]
    fn test_invalid_format() {
        let cwd = Path::new("/tmp");
        let settings = make_settings(vec!["invalid"]);
        assert!(AccessRules::from_settings(&settings, cwd).is_err());
    }

    #[test]
    fn test_unknown_operation() {
        let cwd = Path::new("/tmp");
        let settings = make_settings(vec!["Delete(./file.txt)"]);
        assert!(AccessRules::from_settings(&settings, cwd).is_err());
    }

    #[test]
    fn test_multiple_rules() {
        let cwd = Path::new("/home/user/project");
        let settings = make_settings(vec!["Read(./a.txt)", "Read(./.env)", "Write(./config.json)"]);
        let rules = AccessRules::from_settings(&settings, cwd).unwrap();

        assert!(rules.is_denied(Path::new("/home/user/project/a.txt"), Operation::Read));
        assert!(rules.is_denied(Path::new("/home/user/project/.env"), Operation::Read));
        assert!(rules.is_denied(
            Path::new("/home/user/project/config.json"),
            Operation::Write
        ));
        assert!(!rules.is_denied(
            Path::new("/home/user/project/config.json"),
            Operation::Read
        ));
    }

    #[test]
    fn test_absolute_path() {
        let cwd = Path::new("/tmp");
        let settings = make_settings(vec!["Read(/etc/passwd)"]);
        let rules = AccessRules::from_settings(&settings, cwd).unwrap();

        assert!(rules.is_denied(Path::new("/etc/passwd"), Operation::Read));
    }
}
