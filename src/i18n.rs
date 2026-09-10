use std::borrow::Cow;

pub struct I18n {
    translations: toml::Value,
}

impl I18n {
    pub fn get<'a>(&'a self, key: &'a str) -> Cow<'a, str> {
        let mut current = &self.translations;

        for part in key.split(".") {
            match current.get(part) {
                Some(value) => current = value,

                None => return Cow::Owned(key.to_string()),
            }
        }

        match current.as_str() {
            Some(s) => Cow::Borrowed(s),
            None => Cow::Owned(key.to_string()),
        }
    }
}

pub fn load_language(language: &str) -> I18n {
    let locale_file = match language {
        "zh-TW" => include_str!("../locales/zh-TW.toml"),
        "en-US" => include_str!("../locales/en-US.toml"),

        _ => include_str!("../locales/en-US.toml"),
    };

    let translations: toml::Value =
        toml::from_str(locale_file).expect("Failed to parse locale file");

    I18n { translations }
}
