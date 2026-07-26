use std::io::{self, BufRead};

#[derive(Debug, Clone)]
enum RiskLevel {
    High,
    Medium,
    Low,
}

impl RiskLevel {
    fn rank(&self) -> u8 {
        match self {
            RiskLevel::High => 0,
            RiskLevel::Medium => 1,
            RiskLevel::Low => 2,
        }
    }

    fn as_str(&self) -> &str {
        match self {
            RiskLevel::High => "high",
            RiskLevel::Medium => "medium",
            RiskLevel::Low => "low",
        }
    }
}

#[derive(Debug)]
struct RiskResult {
    id: String,
    days_since_check: i32,
    is_overdue: bool,
    risk: RiskLevel,
}

fn notes_mention_failure(condition_notes: &str) -> bool {
    condition_notes.to_lowercase().contains("fail")
}

fn compute_risk(
    id: String,
    days_since_check: i32,
    check_interval_days: i32,
    condition_notes: &str,
) -> RiskResult {
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

    RiskResult {
        id,
        days_since_check,
        is_overdue,
        risk,
    }
}

fn main() {
    let stdin = io::stdin();
    let mut results = Vec::new();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };

        if line.is_empty() {
            continue;
        }

        let fields: Vec<&str> = line.split('|').collect();

        if fields.len() < 3 {
            continue;
        }

        let id = fields[0].to_string();

        let days_since_check = match fields[1].parse::<i32>() {
            Ok(n) => n,
            Err(_) => 0,
        };

        let check_interval_days = match fields[2].parse::<i32>() {
            Ok(n) => n,
            Err(_) => 0,
        };

        let condition_notes = if fields.len() > 3 {
            fields[3..].join("|")
        } else {
            String::new()
        };

        let result = compute_risk(id, days_since_check, check_interval_days, &condition_notes);
        results.push(result);
    }

    results.sort_by_key(|r| r.risk.rank());

    for result in results {
        println!(
            "{}|{}|{}|{}",
            result.id,
            result.days_since_check,
            if result.is_overdue { 1 } else { 0 },
            result.risk.as_str()
        );
    }
}
