use std::process::Command;

fn main() {
    let git_sha = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout).ok()
            } else {
                None
            }
        })
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());

    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
    let build_ts = std::env::var("SOURCE_DATE_EPOCH").unwrap_or_else(|_| "0".to_string());

    println!("cargo:rustc-env=NINEROUTER_GIT_SHA={git_sha}");
    println!("cargo:rustc-env=NINEROUTER_TARGET={target}");
    println!("cargo:rustc-env=NINEROUTER_BUILD_TIMESTAMP={build_ts}");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
}
