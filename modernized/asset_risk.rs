use std::cmp::Ordering;
use std::fmt;
use std::io::{self, BufRead, BufWriter, Write};

/// Represents the risk level of an asset.
/// Ordered from highest to lowest risk: High > Medium > Low.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
enum RiskLevel {
    High,
    Medium,
    Low,
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RiskLevel::High => write!(f, "high"),
            RiskLevel::Medium => write!(f, "medium"),
            RiskLevel::Low => write!(f, "low"),
        }
    }
}

/// A processed risk result for a single asset.
#[derive(Debug)]
struct RiskResult {
    id: String,
    days_since_check: i32,
    is_overdue: bool,
    risk: RiskLevel,
}

/// Checks whether the condition notes contain the word "fail" (case-insensitive).
/// This function is memory-safe: it converts the entire input string to lowercase
/// using String::to_lowercase(), which allocates dynamically and cannot overflow.
fn notes_mention_failure(condition_notes: &str) -> bool {
    condition_notes.to_lowercase().contains("fail")
}

/// Computes the risk level for an asset based on days since last check,
/// check interval, and condition notes.
/// Returns None if check_interval_days is zero (to avoid division by zero).
/// Invariant: days_since_check and check_interval_days should be non-negative
/// for meaningful business logic, but the function handles any i32 value.
fn compute_risk(
    days_since_check: i32,
    check_interval_days: i32,
    condition_notes: &str,
) -> Option<RiskResult> {
    if check_interval_days == 0 {
        return None;
    }

    let is_overdue = days_since_check > check_interval_days;
    let ratio = days_since_check as f64 / check_interval_days as f64;

    let risk = if ratio >= 2.0 {
        RiskLevel::High
    } else if ratio >= 1.0 {
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    };

    let risk = if notes_mention_failure(condition_notes) {
        RiskLevel::High
    } else {
        risk
    };

    Some(RiskResult {
        id: String::new(),
        days_since_check,
        is_overdue,
        risk,
    })
}

/// Parses a single pipe-delimited input line into a RiskResult.
/// Expected format: id|days_since_check|check_interval_days|condition_notes
/// Returns None if the line is malformed (wrong number of fields or unparseable integers).
/// The condition_notes field may be empty and may be arbitrarily long.
fn parse_record(line: &str) -> Option<RiskResult> {
    let parts: Vec<&str> = line.split('|').collect();
    if parts.len() < 3 {
        return None;
    }

    let id = parts[0];
    let days_since_check = parts[1].parse::<i32>().ok()?;
    let check_interval_days = parts[2].parse::<i32>().ok()?;
    let condition_notes = if parts.len() > 3 { parts[3] } else { "" };

    let mut result = compute_risk(days_since_check, check_interval_days, condition_notes)?;
    result.id = id.to_string();
    Some(result)
}

/// Reads records from stdin, computes risk for each, sorts by risk level (high to low),
/// and writes results to stdout.
/// Uses a buffered writer for efficient output.
/// Skips malformed records silently (matching legacy C behavior).
fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let mut results = Vec::new();

    for line in stdin.lock().lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some(result) = parse_record(trimmed) {
            results.push(result);
        }
    }

    results.sort_by(|a, b| {
        a.risk.cmp(&b.risk)
    });

    let stdout = io::stdout();
    let mut writer = BufWriter::new(stdout.lock());

    for result in results {
        writeln!(
            writer,
            "{}|{}|{}|{}",
            result.id,
            result.days_since_check,
            if result.is_overdue { 1 } else { 0 },
            result.risk
        )?;
    }

    writer.flush()?;
    Ok(())
}
