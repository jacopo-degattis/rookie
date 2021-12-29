use std::io::{Error, ErrorKind};
use std::collections::HashMap;
use openssl::pkcs5::pbkdf2_hmac;
use openssl::hash::MessageDigest;
use rusqlite::{Connection, Result};
extern crate urlparse;
use rusqlite::NO_PARAMS;
use urlparse::urlparse;
extern crate dirs;
extern crate keyring;

#[derive(Debug)]
struct Cooky {
    sl_no: String,
    column_name: String,
    data_type: String,
    is_null: String,
    default_val: String,
    pk: String,
}


fn _get_safe_storage_keyring(browser: &str) -> Result<String, keyring::Error> {


    let service_name = format!("{} Safe Storage", browser);
    // TODO: PUT DYNAMIC FIELD BROWSER NOT CHROME
    let entry = keyring::Entry::new("Chrome Safe Storage", "Chrome");
    
    let password: String = match entry.get_password() {
        Ok(val) => val,
        Err(err) => format!("{}", err),
    };

    Ok(password)
}

fn get_os_config(browser: &str) -> Result<HashMap<&str, String>, Error> {
    /*

    Get settings to fetch chrome cookies based upon
    the currently using OS.

    Args:
        browser: "Chrome" | "Chromium"
    
    Returns:
        Config HashMap for cookies decryption

    */

    // TODO: add config for windows and linux

    let mut config: HashMap<&str, String> = HashMap::new();

    let browser_folding = HashMap::from([
        ("Chrome", "Google/Chrome"),
        ("Chromium", "Chromium")
    ]);

    if !vec!["Chrome", "Chromium"].contains(&browser) {
        return Err(
            Error::new(
                ErrorKind::InvalidInput,
                "Browser must be either 'Chrome' or 'Chromium'"
            )
        );
    }

    let cookie_path = format!(
        "~/Library/Application Support/{}/Default/Cookies",
        browser_folding[browser]
    );

    let password = _get_safe_storage_keyring(browser).unwrap();
    
    config.extend([
        ("psw", password),
        ("iterations", String::from("1003")),
        ("cookie_file", cookie_path)
    ]);

    Ok(config)
}

pub fn chrome_cookies(url: &str, browser: &str) -> Result<HashMap<String, String>, std::io::Error> {
    let mut config: HashMap<&str, String>;
    let e = HashMap::new();

    // TODO: add linux and windows support too
    if cfg!(target_os="macos") {
        config = get_os_config(browser).unwrap();
    } else {
        return Err(
            Error::new(
                ErrorKind::InvalidInput,
                "This scripts only works for OSX or Linux"
            )
        );
    }

    config.extend([
        ("init_vector", (0..16).map(|_| " ").collect::<String>()),
        ("length", String::from("16")),
        ("salt", String::from("sweetsalt"))
    ]);

    let home_dir_str = dirs::home_dir().unwrap();
    let cookie_file = format!(
        "{}{}",
        home_dir_str.to_str().unwrap(),
        config["cookie_file"].replace("~", "")
    );

    let mut salted_password: [u8; 32] = [0; 32];
    
    println!("psw, {}", config["psw"]);

    match pbkdf2_hmac(
        config["psw"].as_bytes(),
        &config["salt"].as_bytes(),
        config["iterations"].parse::<usize>().unwrap(),
        MessageDigest::sha1(),
        &mut salted_password
    ) {
        Ok(val) => String::from("ok"),
        Err(err) => format!("{}", err)
    };

    println!("psw, {:x?}", salted_password);

    // TODO: use aes_gcm do decrypt AES packages
    let parsed_url = urlparse(url);
    
    if parsed_url.scheme.chars().count() == 0 {
        return Err(
            Error::new(
                // TODO: change error kind
                ErrorKind::InvalidInput,
                "You must specify a scheme with your URL"
            )
        );
    }

    let domain = parsed_url.netloc;

    // TODO: imrove error catching for DB connection
    // TODO: move to dedicated function, it also fixes the exception error
    // let conn = Connection::open(cookie_file).unwrap();

    // let mut query = conn.prepare("PRAGMA table_info(cookies)")?;
    // let cookies = query.query_map(NO_PARAMS, |row| {
    //     Ok(Cooky {
    //         sl_no: row.get(0)?,
    //     })
    // });

    Ok(e)
} 