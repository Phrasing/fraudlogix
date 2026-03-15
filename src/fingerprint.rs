use crate::types::{BehaviorMetrics, BrowserFingerprint, ScreenInfo};
use rand::Rng;
use serde_json::json;

const SCREENS: [(u32, u32); 5] = [
    (1920, 1080),
    (2560, 1440),
    (1366, 768),
    (1536, 864),
    (1440, 900),
];

const HW_CONCURRENCY: [u8; 4] = [4, 8, 12, 16];
const DEVICE_MEMORY: [u8; 3] = [4, 8, 16];

pub fn random_fingerprint() -> (BrowserFingerprint, ScreenInfo) {
    let mut rng = rand::thread_rng();
    let (width, height) = SCREENS[rng.gen_range(0..SCREENS.len())];

    let fp = BrowserFingerprint {
        plugins: "PDF Viewer,Chrome PDF Viewer,Chromium PDF Viewer,Microsoft Edge PDF Viewer,WebKit built-in PDF",
        mime_types: "application/pdf,text/pdf",
        do_not_track: "unknown",
        hardware_concurrency: HW_CONCURRENCY[rng.gen_range(0..HW_CONCURRENCY.len())],
        device_memory: DEVICE_MEMORY[rng.gen_range(0..DEVICE_MEMORY.len())],
        language: "en-US",
        languages: "en-US,en",
    };

    let screen = ScreenInfo {
        width,
        height,
        color_depth: if width < 2560 { 24 } else { 32 },
        orientation: "landscape-primary",
    };

    (fp, screen)
}

pub fn random_behavior() -> BehaviorMetrics {
    let mut rng = rand::thread_rng();
    BehaviorMetrics {
        mouse_movements: rng.gen_range(15..=85),
        keystrokes: rng.gen_range(0..=4),
        scroll_events: rng.gen_range(0..=8),
        click_events: rng.gen_range(1..=5),
        touch_events: 0,
        time_on_page: rng.gen_range(2000..=8000),
        focus_changes: rng.gen_range(0..=3),
    }
}

pub fn generate_browser_data(nonce: &str, transformed_nonce: &str, user_agent: &str) -> String {
    let (fp, screen) = random_fingerprint();
    let behavior = random_behavior();

    let fp_hash = crate::pow::fingerprint_hash(
        &serde_json::to_string(&json!({
            "fingerprint": fp,
            "behavior": behavior
        }))
        .unwrap(),
        transformed_nonce,
    );

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();

    let nonce_prefix = if nonce.len() >= 8 { &nonce[..8] } else { nonce };

    serde_json::to_string(&json!({
        "screen": screen,
        "ua": user_agent,
        "h": fp_hash,
        "n": format!("{}...", nonce_prefix),
        "t": timestamp
    }))
    .unwrap()
}

pub fn random_request_id() -> String {
    let mut rng = rand::thread_rng();
    let len = rng.gen_range(11..=13);

    (0..len)
        .map(|_| {
            let chars = b"abcdefghijklmnopqrstuvwxyz0123456789";
            chars[rng.gen_range(0..chars.len())] as char
        })
        .collect()
}
