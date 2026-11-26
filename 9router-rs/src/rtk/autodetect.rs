use super::DETECT_WINDOW;

/// Authoritative 12-filter detection order (ported from open-sse/rtk/autodetect.js).
pub fn detect_filter(input: &str) -> Option<&'static str> {
    let end = input.floor_char_boundary(DETECT_WINDOW.min(input.len()));
    let head = &input[..end];

    if head.contains("diff --git ") || (head.contains("--- a/") && head.contains("+++ b/")) {
        return Some("git_diff");
    }
    if head.contains("On branch ")
        && (head.contains("Changes not staged")
            || head.contains("Untracked files:")
            || head.contains("Changes to be committed"))
    {
        return Some("git_status");
    }
    if head.starts_with("commit ") && head.contains("\nAuthor:") && head.contains("\nDate:") {
        return Some("git_log");
    }
    if head.contains("├── ") || head.contains("└── ") || head.contains("│   ") {
        return Some("tree");
    }
    if looks_like_ls_long(head) {
        return Some("ls");
    }
    if looks_like_read_numbered(head) {
        return Some("read_numbered");
    }
    if looks_like_build_output(head) {
        return Some("build_output");
    }
    if looks_like_grep(head) {
        return Some("grep");
    }
    if looks_like_find(head) {
        return Some("find");
    }
    if looks_like_search_list(head) {
        return Some("search_list");
    }
    if looks_like_log(head) {
        return Some("dedup_log");
    }
    Some("smart_truncate")
}

fn looks_like_ls_long(head: &str) -> bool {
    let mut hits = 0usize;
    for line in head.lines().take(10) {
        let b = line.as_bytes();
        if b.len() >= 10
            && matches!(b[0], b'-' | b'd' | b'l')
            && matches!(b[1], b'r' | b'-')
            && matches!(b[2], b'w' | b'-')
        {
            hits += 1;
        }
    }
    hits >= 3
}

fn looks_like_read_numbered(head: &str) -> bool {
    let mut hits = 0usize;
    for line in head.lines().take(8) {
        let trimmed = line.trim_start();
        if let Some((num, rest)) = trimmed
            .split_once('\t')
            .or_else(|| trimmed.split_once(" | "))
            .or_else(|| trimmed.split_once(": "))
            && !num.is_empty()
            && num.bytes().all(|b| b.is_ascii_digit())
            && !rest.is_empty()
        {
            hits += 1;
        }
    }
    hits >= 4
}

fn looks_like_build_output(head: &str) -> bool {
    head.contains("Compiling ")
        || head.contains("Running `")
        || head.contains("npm WARN")
        || head.contains("webpack")
        || head.contains("cargo test")
        || head.contains("PASS ")
        || head.contains("FAIL ")
}

fn looks_like_grep(head: &str) -> bool {
    let mut hits = 0usize;
    for line in head.lines().take(10) {
        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() == 3
            && !parts[0].is_empty()
            && !parts[0].contains(' ')
            && !parts[1].is_empty()
            && parts[1].bytes().all(|b| b.is_ascii_digit())
        {
            hits += 1;
        }
    }
    hits >= 3
}

fn looks_like_find(head: &str) -> bool {
    let mut hits = 0usize;
    for line in head.lines().take(12) {
        let l = line.trim();
        if (l.starts_with("./") || l.starts_with('/') || l.contains('/')) && !l.contains(' ') {
            hits += 1;
        }
    }
    hits >= 5
}

fn looks_like_search_list(head: &str) -> bool {
    let mut hits = 0usize;
    for line in head.lines().take(10) {
        let l = line.trim_start();
        if l.starts_with("- ")
            || l.starts_with("* ")
            || l.starts_with("http://")
            || l.starts_with("https://")
        {
            hits += 1;
        }
    }
    hits >= 4
}

fn looks_like_log(head: &str) -> bool {
    let mut hits = 0usize;
    for line in head.lines().take(10) {
        if line.contains("INFO")
            || line.contains("WARN")
            || line.contains("DEBUG")
            || line.contains("ERROR")
        {
            hits += 1;
        }
    }
    hits >= 3
}
