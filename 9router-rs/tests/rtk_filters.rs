use ninerouter_rs::config::schema::RtkConfig;
use ninerouter_rs::rtk::apply_pre_translate;
use ninerouter_rs::rtk::autodetect::detect_filter;
use ninerouter_rs::rtk::filters::run_filter;
use serde_json::json;

#[test]
fn detects_and_compresses_git_diff_and_preserves_is_error() {
    let mut big_diff = String::from("diff --git a/src/a.rs b/src/a.rs\nindex 111..222 100644\n--- a/src/a.rs\n+++ b/src/a.rs\n@@ -1,40 +1,41 @@\n");
    for i in 0..40 {
        big_diff.push_str(&format!(" unchanged context line {i}\n"));
    }
    big_diff.push_str("+let added = 1;\n");

    assert_eq!(detect_filter(&big_diff), Some("git_diff"));
    let compressed = run_filter("git_diff", &big_diff).unwrap();
    assert!(compressed.len() < big_diff.len());
    assert!(compressed.contains("+let added = 1;"));

    let mut body = json!({
        "model": "anthropic/claude-sonnet-4-5",
        "system": "<env>windows</env>",
        "messages": [
            {
                "role": "user",
                "content": [
                    { "type": "tool_result", "tool_use_id": "t1", "content": big_diff, "is_error": false },
                    { "type": "tool_result", "tool_use_id": "t2", "content": big_diff, "is_error": true }
                ]
            }
        ]
    });

    let cfg = RtkConfig {
        enabled: true,
        caveman_level: "full".to_string(),
        ponytail_level: "ultra".to_string(),
        custom_prompt: "Prefer Rust std.".to_string(),
    };

    let outcome = apply_pre_translate(&mut body, &cfg, false);
    assert_eq!(outcome.compressed_blocks, 1);
    assert!(outcome.tokens_saved_est > 0);
    // Error result must remain untouched
    assert_eq!(body["messages"][0]["content"][1]["content"].as_str().unwrap(), big_diff);
    // System prompt must preserve <env> while appending modifiers
    let sys = body["system"].as_str().unwrap();
    assert!(sys.contains("<env>windows</env>"));
    assert!(sys.contains("Prefer Rust std."));
}

#[test]
fn bypass_header_and_multibyte_utf8_window_are_safe() {
    let mut utf8_payload = "é".repeat(600); // multi-byte chars crossing byte 1024
    utf8_payload.push_str("\nINFO repeat\n");
    let _ = detect_filter(&utf8_payload); // must never panic on char boundary

    let mut body = json!({
        "model": "openai/gpt-4.1",
        "messages": [{ "role": "tool", "content": utf8_payload }]
    });
    let cfg = RtkConfig::default();
    let outcome = apply_pre_translate(&mut body, &cfg, true);
    assert_eq!(outcome.compressed_blocks, 0);
}
