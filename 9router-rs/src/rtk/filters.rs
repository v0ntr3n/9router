use std::collections::BTreeMap;

pub fn run_filter(name: &str, input: &str) -> Option<String> {
    match name {
        "git_diff" => Some(filter_git_diff(input)),
        "git_status" => Some(filter_git_status(input)),
        "git_log" => Some(filter_git_log(input)),
        "grep" => Some(filter_grep(input)),
        "find" => Some(filter_find(input)),
        "ls" => Some(filter_ls(input)),
        "tree" => Some(filter_tree(input)),
        "build_output" => Some(filter_build_output(input)),
        "dedup_log" => Some(filter_dedup_log(input)),
        "read_numbered" => Some(filter_read_numbered(input)),
        "search_list" => Some(filter_search_list(input)),
        "smart_truncate" => Some(filter_smart_truncate(input)),
        _ => None,
    }
}

fn filter_git_diff(input: &str) -> String {
    let mut out = Vec::new();
    let mut skipped_ctx = 0usize;
    for line in input.lines() {
        if line.starts_with("index ")
            || line.starts_with("old mode ")
            || line.starts_with("new mode ")
        {
            continue;
        }
        if line.starts_with("diff --git ")
            || line.starts_with("--- ")
            || line.starts_with("+++ ")
            || line.starts_with("@@ ")
            || line.starts_with('+')
            || line.starts_with('-')
        {
            if skipped_ctx > 0 {
                out.push(format!("  ... ({skipped_ctx} unchanged lines)"));
                skipped_ctx = 0;
            }
            out.push(line.to_string());
        } else {
            skipped_ctx += 1;
        }
    }
    if skipped_ctx > 0 {
        out.push(format!("  ... ({skipped_ctx} unchanged lines)"));
    }
    out.join("\n")
}

fn filter_git_status(input: &str) -> String {
    let mut out = Vec::new();
    for line in input.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('(') {
            continue;
        }
        out.push(t.to_string());
    }
    out.join("\n")
}

fn filter_git_log(input: &str) -> String {
    let mut out = Vec::new();
    let mut cur_hash = String::new();
    for line in input.lines() {
        if let Some(rest) = line.strip_prefix("commit ") {
            cur_hash = rest.chars().take(8).collect();
        } else if line.starts_with("Author:") || line.starts_with("Date:") || line.trim().is_empty()
        {
            continue;
        } else if !cur_hash.is_empty() {
            out.push(format!("{cur_hash} {}", line.trim()));
            cur_hash.clear();
        }
    }
    out.join("\n")
}

fn filter_grep(input: &str) -> String {
    let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for line in input.lines() {
        let mut parts = line.splitn(3, ':');
        if let (Some(file), Some(lno), Some(body)) = (parts.next(), parts.next(), parts.next()) {
            grouped
                .entry(file.to_string())
                .or_default()
                .push(format!("{lno}:{}", body.trim()));
        }
    }
    let mut out = Vec::new();
    for (file, matches) in grouped {
        out.push(format!("{file} ({}):", matches.len()));
        for m in matches.iter().take(25) {
            out.push(format!("  {m}"));
        }
        if matches.len() > 25 {
            out.push(format!("  ... (+{} more)", matches.len() - 25));
        }
    }
    out.join("\n")
}

fn filter_find(input: &str) -> String {
    let mut by_dir: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for line in input.lines() {
        let l = line.trim();
        if l.is_empty() {
            continue;
        }
        match l.rsplit_once('/') {
            Some((dir, file)) => by_dir
                .entry(dir.to_string())
                .or_default()
                .push(file.to_string()),
            None => by_dir.entry(".".to_string()).or_default().push(l.to_string()),
        }
    }
    let mut out = Vec::new();
    for (dir, files) in by_dir {
        if files.len() <= 12 {
            out.push(format!("{dir}/: {}", files.join(", ")));
        } else {
            out.push(format!(
                "{dir}/ ({}): {}, ... (+{})",
                files.len(),
                files[..10].join(", "),
                files.len() - 10
            ));
        }
    }
    out.join("\n")
}

fn filter_ls(input: &str) -> String {
    let mut entries = Vec::new();
    for line in input.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 9 {
            let kind = if cols[0].starts_with('d') { "/" } else { "" };
            entries.push(format!("{}{kind} ({})", cols[8..].join(" "), cols[4]));
        } else if !line.trim().is_empty() && !line.starts_with("total ") {
            entries.push(line.trim().to_string());
        }
    }
    entries.join("\n")
}

fn filter_tree(input: &str) -> String {
    let lines: Vec<&str> = input.lines().collect();
    if lines.len() <= 60 {
        return lines
            .into_iter()
            .map(str::trim_end)
            .collect::<Vec<_>>()
            .join("\n");
    }
    let mut out: Vec<String> = lines[..45].iter().map(|s| s.trim_end().to_string()).collect();
    out.push(format!("... ({} tree lines omitted)", lines.len() - 55));
    out.extend(lines[lines.len() - 10..].iter().map(|s| s.trim_end().to_string()));
    out.join("\n")
}

fn filter_build_output(input: &str) -> String {
    let mut out = Vec::new();
    let mut suppressed = 0usize;
    for line in input.lines() {
        let lower = line.to_ascii_lowercase();
        let keep = lower.contains("error")
            || lower.contains("warn")
            || lower.contains("fail")
            || lower.contains("test result:")
            || lower.contains("finished ");
        if keep {
            if suppressed > 0 {
                out.push(format!("... ({suppressed} build lines skipped)"));
                suppressed = 0;
            }
            out.push(line.trim_end().to_string());
        } else {
            suppressed += 1;
        }
    }
    if suppressed > 0 {
        out.push(format!("... ({suppressed} build lines skipped)"));
    }
    out.join("\n")
}

fn filter_dedup_log(input: &str) -> String {
    let mut out = Vec::new();
    let mut prev: Option<&str> = None;
    let mut count = 0usize;
    for line in input.lines() {
        let t = line.trim_end();
        if Some(t) == prev {
            count += 1;
        } else {
            if let Some(p) = prev {
                if count > 1 {
                    out.push(format!("{p} [x{count}]"));
                } else {
                    out.push(p.to_string());
                }
            }
            prev = Some(t);
            count = 1;
        }
    }
    if let Some(p) = prev {
        if count > 1 {
            out.push(format!("{p} [x{count}]"));
        } else {
            out.push(p.to_string());
        }
    }
    out.join("\n")
}

fn filter_read_numbered(input: &str) -> String {
    let mut out = Vec::new();
    let mut blank_run = 0usize;
    for line in input.lines() {
        let trimmed = line.trim();
        let is_blank_code = trimmed
            .split_once('\t')
            .or_else(|| trimmed.split_once('|'))
            .map(|(_, rest)| rest.trim().is_empty())
            .unwrap_or(trimmed.is_empty());
        if is_blank_code {
            blank_run += 1;
            if blank_run == 1 {
                out.push(String::new());
            }
        } else {
            blank_run = 0;
            out.push(line.trim_end().to_string());
        }
    }
    out.join("\n")
}

fn filter_search_list(input: &str) -> String {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for line in input.lines() {
        let t = line.trim();
        if t.is_empty() || !seen.insert(t.to_string()) {
            continue;
        }
        out.push(t.to_string());
    }
    out.join("\n")
}

fn filter_smart_truncate(input: &str) -> String {
    let lines: Vec<&str> = input.lines().collect();
    if lines.len() <= 80 {
        return input.to_string();
    }
    let mut out: Vec<String> = lines[..50].iter().map(|s| (*s).to_string()).collect();
    out.push(format!("... ({} lines truncated) ...", lines.len() - 70));
    out.extend(lines[lines.len() - 20..].iter().map(|s| (*s).to_string()));
    out.join("\n")
}
