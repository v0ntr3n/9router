use ninerouter_rs::config::load_opencode_profile;
use ninerouter_rs::providers::opencode_fingerprint::{
    OpenCodeSessionStore, apply_opencode_fingerprint, restore_tool_names_in_text,
};
use serde_json::json;
use tempfile::tempdir;

#[test]
fn opencode_profile_has_exact_17_boringssl_ciphers() {
    let dir = tempdir().unwrap();
    let profile = load_opencode_profile(dir.path()).unwrap();
    assert_eq!(profile.cipher_list.len(), 17);
    assert_eq!(profile.cipher_list[0], "TLS_AES_128_GCM_SHA256");
    assert_eq!(profile.cipher_list[16], "AES256-SHA");
}

#[test]
fn session_lru_and_value_matched_invalidation() {
    let store = OpenCodeSessionStore::new(2);
    let s1 = store.get_or_mint("caller-1");
    assert!(s1.starts_with("ses_"));
    assert_eq!(s1.len(), 4 + 12 + 14);
    assert_eq!(store.get_or_mint("caller-1"), s1);

    // Mismatched value must not invalidate
    assert!(!store.invalidate_if_matches("caller-1", "ses_wrong"));
    assert_eq!(store.len(), 1);

    // Exact value match invalidates
    assert!(store.invalidate_if_matches("caller-1", &s1));
    assert_eq!(store.len(), 0);
}

#[test]
fn fingerprint_aliases_tools_appends_missing_and_restores_response() {
    let dir = tempdir().unwrap();
    let profile = load_opencode_profile(dir.path()).unwrap();
    let mut body = json!({
        "model": "gpt-5-nano",
        "input": [
            { "type": "function_call", "call_id": "c1", "name": "run_terminal_cmd", "arguments": "{}" }
        ],
        "tools": [
            { "type": "function", "name": "run_terminal_cmd", "parameters": { "type": "object" } },
            { "type": "function", "name": "read", "parameters": { "type": "object" } }
        ]
    });

    let report = apply_opencode_fingerprint(&mut body, &profile, "ses_000000000000ABCDEFGHIJKLMN".into());
    assert_eq!(body["stream"], true);
    assert_eq!(body["tool_choice"], "auto");
    assert_eq!(body["input"][0]["name"], "run_command");
    assert_eq!(report.aliased_tools.get("run_command").map(String::as_str), Some("run_terminal_cmd"));
    assert_eq!(report.aliased_tools.get("read_client").map(String::as_str), Some("read"));
    assert!(report.tools_appended.contains(&"read".to_string()));
    assert!(report.tools_appended.contains(&"shell".to_string()));
    assert!(body["instructions"].as_str().unwrap().contains("unavailable"));

    let restored = restore_tool_names_in_text(
        r#"data: {"name":"run_command","arguments":"{}"}"#,
        &report.aliased_tools,
    );
    assert!(restored.contains("\"name\":\"run_terminal_cmd\""));
}
