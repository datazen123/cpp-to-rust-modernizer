use std::io::{self, BufRead};

#[derive(Clone)]
struct RiskResult {
    id: String,
    days_since_check: i32,
    is_overdue: bool,
    risk: String,
}

fn notes_mention_failure(condition_notes: &str) -> bool {
    condition_notes.to_lowercase().contains("fail")
}

fn compute_risk(days_since_check: i32, check_interval_days: i32, condition_notes: &str) -> RiskResult {
    let is_overdue = days_since_check > check_interval_days;
    
    let ratio = days_since_check as f64 / check_interval_days as f64;
    let mut risk = if ratio >= 2.0 {
        String::from("high")
    } else if ratio >= 1.0 {
        String::from("medium")
    } else {
        String::from("low")
    };
    
    if notes_mention_failure(condition_notes) {
        risk = String::from("high");
    }
    
    RiskResult {
        id: String::new(),
        days_since_check,
        is_overdue,
        risk,
    }
}

fn risk_rank(risk: &str) -> u8 {
    match risk {
        "high" => 0,
        "medium" => 1,
        _ => 2,
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
        
        let id = fields[0];
        let days_str = fields[1];
        let interval_str = fields[2];
        let notes = if fields.len() > 3 {
            fields[3]
        } else {
            ""
        };
        
        let days_since_check = match days_str.parse::<i32>() {
            Ok(v) => v,
            Err(_) => continue,
        };
        
        let check_interval_days = match interval_str.parse::<i32>() {
            Ok(v) => v,
            Err(_) => continue,
        };
        
        let mut result = compute_risk(days_since_check, check_interval_days, notes);
        result.id = id.to_string();
        results.push(result);
    }
    
    results.sort_by_key(|r| risk_rank(&r.risk));
    
    for result in results {
        println!("{}|{}|{}|{}", 
            result.id, 
            result.days_since_check, 
            if result.is_overdue { 1 } else { 0 },
            result.risk
        );
    }
}
