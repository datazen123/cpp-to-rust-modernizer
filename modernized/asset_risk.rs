use std::cmp::Ordering;
use std::fmt;
use std::io::{self, BufRead, BufWriter, Write};

/// Risk level tier for an asset, ordered high > medium > low for sorting.
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

/// A parsed and scored asset risk record.
#[derive(Debug)]
struct RiskResult {
    id: String,
    days_since_check: i32,
    is_overdue: bool,
    risk: RiskLevel,
}

/// Checks whether the condition notes mention failure (case-insensitive substring search).
/// Invariant: safely handles arbitrarily long condition_notes via heap-allocated String.
fn notes_mention_failure(condition_notes: &str) -> bool {
    condition_notes.to_lowercase().contains("fail")
}

/// Computes the risk level for an asset based on check interval ratio and condition notes.
/// Invariant: check_interval_days > 0 assumed by caller for valid ratio calculation.
fn compute_risk(
    days_since_check: i32,
    check_interval_days: i32,
    condition_notes: &str,
) -> (bool, RiskLevel) {
    let is_overdue = days_since_check > check_interval_days;

    let ratio = days_since_check as f64 / check_interval_days as f64;
    let mut risk = if ratio >= 2.0 {
        RiskLevel::High
    } else if ratio >= 1.0 {
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    };

    if notes_mention_failure(condition_notes) {
        risk = RiskLevel::High;
    }

    (is_overdue, risk)
}

/// Parses a single input line into a RiskResult.
/// Returns None if the line is malformed (missing required fields or invalid integers).
/// Invariant: fields are pipe-delimited; condition_notes may be absent or arbitrarily long.
fn parse_record(line: &str) -> Option<RiskResult> {
    let mut fields = line.split('|');

    let id = fields.next()?.trim();
    if id.is_empty() {
        return None;
    }

    let days_str = fields.next()?.trim();
    let days_since_check = days_str.parse::<i32>().ok()?;

    let interval_str = fields.next()?.trim();
    let check_interval_days = interval_str.parse::<i32>().ok()?;

    if check_interval_days <= 0 {
        return None;
    }

    let condition_notes = fields.next().unwrap_or("").trim();

    let (is_overdue, risk) = compute_risk(days_since_check, check_interval_days, condition_notes);

    Some(RiskResult {
        id: id.to_string(),
        days_since_check,
        is_overdue,
        risk,
    })
}

/// Reads all records from stdin, parses and scores them.
/// Returns a vector of valid RiskResult records, silently skipping malformed lines.
/// Invariant: no fixed capacity limit; handles arbitrarily many records within memory constraints.
fn read_records() -> io::Result<Vec<RiskResult>> {
    let stdin = io::stdin();
    let mut results = Vec::new();

    for line_result in stdin.lock().lines() {
        let line = line_result?;
        let trimmed = line.trim();

        if trimmed.is_empty() {
            continue;
        }

        if let Some(record) = parse_record(trimmed) {
            results.push(record);
        }
    }

    Ok(results)
}

/// Sorts records by risk level (high first, then medium, then low).
/// Invariant: RiskLevel's derived Ord ensures high < medium < low in enum order.
fn sort_by_risk(results: &mut [RiskResult]) {
    results.sort_by_key(|r| r.risk);
}

/// Writes all records to stdout in pipe-delimited format, one per line.
/// Uses a locked buffered writer for efficient bulk output.
/// Invariant: output format is id|days_since_check|is_overdue|risk.
fn write_results(results: &[RiskResult]) -> io::Result<()> {
    let stdout = io::stdout();
    let mut writer = BufWriter::new(stdout.lock());

    for r in results {
        writeln!(
            writer,
            "{}|{}|{}|{}",
            r.id,
            r.days_since_check,
            if r.is_overdue { 1 } else { 0 },
            r.risk
        )?;
    }

    writer.flush()?;
    Ok(())
}

/// Main entry point: reads asset records from stdin, scores them, sorts by risk, writes to stdout.
fn main() -> io::Result<()> {
    let mut results = read_records()?;
    sort_by_risk(&mut results);
    write_results(&results)?;
    Ok(())
}
