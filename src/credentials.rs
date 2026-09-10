use keyring::Entry;

const SERVICE_NAME: &str = env!("CARGO_PKG_NAME");
const USERNAME_ENTRY: &str = "__username__";

pub fn save_credentials(username: &str, password: &str) -> Result<(), keyring::Error> {
    let entry = Entry::new(SERVICE_NAME, username)?;
    entry.set_password(password)?;

    let username_entry = Entry::new(SERVICE_NAME, USERNAME_ENTRY)?;
    username_entry.set_password(username)?;

    Ok(())
}

pub fn load_credentials() -> Result<(String, String), keyring::Error> {
    let username_entry = Entry::new(SERVICE_NAME, USERNAME_ENTRY)?;
    let username = username_entry.get_password()?;

    let entry = Entry::new(SERVICE_NAME, &username)?;
    let password = entry.get_password()?;

    Ok((username, password))
}
