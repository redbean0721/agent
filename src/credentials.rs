use keyring::Entry;

const SERVICE_NAME: &str = env!("CARGO_PKG_NAME");
const TOKEN_ENTRY: &str = "__token__";

pub fn save_token(token: &str) -> Result<(), keyring::Error> {
    let entry = Entry::new(SERVICE_NAME, TOKEN_ENTRY)?;
    entry.set_password(token)?;

    Ok(())
}

pub fn load_token() -> Result<String, keyring::Error> {
    let entry = Entry::new(SERVICE_NAME, TOKEN_ENTRY)?;
    entry.get_password()
}
