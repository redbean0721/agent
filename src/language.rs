pub fn get_system_locale() -> String {
    let locale = sys_locale::get_locale().unwrap_or_else(|| "en-US".to_string());

    normalize_locale(&locale)
}
fn normalize_locale(locale: &str) -> String {
    let locale = locale.replace("_", "-");

    let locale = locale.split(".").next().unwrap_or(&locale);
    match locale {
        "zh" => "zh-TW".to_string(),
        "en" => "en-US".to_string(),
        "ja" => "ja-JP".to_string(),
        _ => locale.to_string(),
    }
}
