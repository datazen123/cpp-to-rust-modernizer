use std::cmp::Ordering;
use std::fmt;
use std::io::{self, BufRead, BufWriter, Write};

/// Risk tier enumeration: High, Medium, or Low.
/// Ordered such that High < Medium < Low for sorting (highest risk first).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum RiskLevel {
    High,
    Medium,
    Low,
}

impl PartialOrd for RiskLevel {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RiskLevel {
    fn cmp(&self, other: &Self) -> Ordering {
        let self_rank = match self {
            RiskLevel::High => 0,
            RiskLevel::Medium => 1,
            RiskLevel::Low => 2,
        };
        let other_rank = match other {
            RiskLevel::High => 0,
            RiskLevel::Medium => 1,
            RiskLevel::Low => 2,
        };
        self_rank.cmp(&other_rank)
    }
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            RiskLevel::High => "high",
            RiskLevel::Medium => "medium",
            RiskLevel::Low => "low",
        };
        write!(f, "{}", s)
    }
}

/// Parsed input record: asset ID, days since last check, check interval, and condition notes.
#[derive(Debug)]
struct Record {
    id: String,
    days_since_check: i32,
    check_interval_days: i32,
    condition_notes: String,
}

/// Computed risk result: asset ID, days since check, overdue flag, and risk tier.
#[derive(Debug)]
struct RiskResult {
    id: String,
    days_since_check: i32,
    is_overdue: bool,
    risk: RiskLevel,
}

/// Checks if the condition notes contain the word "fail" (case-insensitive).
/// Returns true if "fail" is found, false otherwise.
/// This function allocates a new lowercase String, avoiding any fixed-size buffer overflow.
fn notes_mention_failure(condition_notes: &str) -> bool {
    condition_notes.to_lowercase().contains("fail")
}

/// Computes the risk result for a given record.
/// Returns a RiskResult with the overdue flag and risk tier.
/// Invariant: check_interval_days must be > 0 (caller validated).
fn compute_risk(record: &Record) -> RiskResult {
    let is_overdue = record.days_since_check > record.check_interval_days;
    
    let ratio = record.days_since_check as f64 / record.check_interval_days as f64;
    
    let mut risk = if ratio >= 2.0 {
        RiskLevel::High
    } else if ratio >= 1.0 {
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    };
    
    if notes_mention_failure(&record.condition_notes) {
        risk = RiskLevel::High;
    }
    
    RiskResult {
        id: record.id.clone(),
        days_since_check: record.days_since_check,
        is_overdue,
        risk,
    }
}

/// Parses a single line into a Record.
/// Returns Some(Record) if the line is valid, None otherwise.
/// A valid line has exactly 4 pipe-delimited fields; the fourth (condition_notes) may be empty.
fn parse_line(line: &str) -> Option<Record> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    
    let parts: Vec<&str> = trimmed.split('|').collect();
    if parts.len() < 3 {
        return None;
    }
    
    let id = parts[0].to_string();
    let days_since_check = parts[1].parse::<i32>().ok()?;
    let check_interval_days = parts[2].parse::<i32>().ok()?;
    
    if check_interval_days <= 0 {
        return None;
    }
    
    let condition_notes = if parts.len() >= 4 {
        parts[3..].join("|")
    } else {
        String::new()
    };
    
    Some(Record {
        id,
        days_since_check,
        check_interval_days,
        condition_notes,
    })
}

/// Main entry point: reads records from stdin, computes risk, sorts by risk tier, and writes to stdout.
/// All I/O is buffered; no fixed-size buffers are used for parsing or storage.
fn main() {
    let stdin = io::stdin();
    let mut results: Vec<RiskResult> = Vec::new();
    
    for line_result in stdin.lock().lines() {
        let line = match line_result {
            Ok(l) => l,
            Err(_) => continue,
        };
        
        if let Some(record) = parse_line(&line) {
            let result = compute_risk(&record);
            results.push(result);
        }
    }
    
    results.sort_by_key(|r| r.risk);
    
    let stdout = io::stdout();
    let mut writer = BufWriter::new(stdout.lock());
    
    for result in results {
        let is_overdue_flag = if result.is_overdue { 1 } else { 0 };
        writeln!(
            writer,
            "{}|{}|{}|{}",
            result.id,
            result.days_since_check,
            is_overdue_flag,
            result.risk
        ).unwrap();
    }
    
    writer.flush().unwrap();
}
