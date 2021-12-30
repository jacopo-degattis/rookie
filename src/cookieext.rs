use std::io::{Error, ErrorKind};
use std::collections::HashMap;
use openssl::pkcs5::pbkdf2_hmac;
use openssl::hash::MessageDigest;
use rusqlite::{Connection, Result};
extern crate urlparse;
use urlparse::urlparse;
extern crate dirs;
extern crate keyring;

#[derive(Debug)]
struct TableInfo {
    sl_no: i32,
    column_name: String,
    data_type: String,
    is_null: i32,
    default_val: Option<String>,
    pk: i32,
}


#[derive(Debug)]
struct Cooky {
    hk: String,
    path: String,
    is_secure: bool,
    expires_utc: i64,
    cookie_key: String,
    val: String,
    enc_val:  Vec<u8>
}

// https://docs.rs/rusqlite/0.13.0/rusqlite/blob/index.html

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

fn _fetch_cookie_table_info_from_db(conn: &Connection, cookie_file: &String) -> Result<Vec<TableInfo>, rusqlite::Error> {
    let mut infos: Vec<TableInfo> = Vec::new();

    let mut query = conn.prepare("PRAGMA table_info(cookies)")?;
    let cookies = query.query_map([], |row| {
        Ok(TableInfo {
            sl_no: row.get(0)?,
            column_name: row.get(1)?,
            data_type: row.get(2)?,
            is_null: row.get(3)?,
            default_val: row.get(4)?,
            pk: row.get(5)?,
        })
    })?;

    for c in cookies {
        infos.push(c.unwrap());
    }

    Ok(infos)
}


fn _generate_host_keys(hostname: &String) -> Result<Vec<String>, std::io::Error> {
    let mut labels = hostname.split(".");
    let vec: Vec<&str> = labels.collect();
    let mut entries: Vec<String> = Vec::new();

    for i in 2..vec.len() + 1 {
        let domain = vec[vec.len() - i .. 3].join(".");
        let formatted = format!(".{}", domain.clone());
        entries.extend([domain, formatted]);
    }
    
    Ok(entries)
}

fn _fetch_cookies_from_db(conn: &Connection, cookie_file: &String, domain: &String, secure_column_name: &String) -> Result<Vec<Cooky>, rusqlite::Error> {
    let cookies: Vec<Cooky> = Vec::new();
    
    let keys = _generate_host_keys(&domain).unwrap();
    


    // let query = format!("select host_key, path, {}, expires_utc, name, value, encrypted_value from cookies where host_key like (?1)", secure_column_name).as_str();

    for host_key in keys {
        // let query = match conn.prepare(
        //     format!("select host_key, path, {}, expires_utc, name, value, encrypted_value from cookies where host_key like '{}'", secure_column_name, host_key).as_str(),
        // ) {
        //     Ok(val) => println!("val, {:?}", val),
        //     Err(err) => println!("err, {}", err)
        // };
        let mut query = conn.prepare(
            format!("select host_key, path, {}, expires_utc, name, value, encrypted_value from cookies where host_key like '{}'", secure_column_name, host_key).as_str(),
        )?;

        let ckies = match query.query_map([], |row| {
            Ok(Cooky {
                hk: row.get(0)?,
                path: row.get(1)?,
                is_secure: row.get(2)?,
                expires_utc: row.get(3)?,
                cookie_key: row.get(4)?,
                val: row.get(5)?,
                enc_val: row.get(6)?
            })
        }) {

            // TODO: improve error handling and match nesting
            Ok(val) => {
                for c in val {
                    match c {
                        Ok(v) => println!("{:?}", v),
                        Err(e) => println!("{:?}", e)
                    }
                }
            },
            Err(err) => println!("err, {}", err)
        };

        // for c in cookies {
        //     let a = c.unwrap();
        //     println!("{:?}", a);
        // }
    }

    Ok(cookies)
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

    let conn = Connection::open(cookie_file.as_str()).unwrap();
    // TODO: imrove error catching for DB connection

    let table_infos = _fetch_cookie_table_info_from_db(&conn, &cookie_file).unwrap();

    let mut secure_column_name = "";
    for info in table_infos {
        if info.column_name == "is_secure" {
            secure_column_name = "is_secure";
        }
    }

    println!("data, {}", secure_column_name);    

    // NOTE: move value, not implement trait copy fix:
    // https://stackoverflow.com/questions/28800121/what-do-i-have-to-do-to-solve-a-use-of-moved-value-error

    let cookies = _fetch_cookies_from_db(&conn, &cookie_file, &domain, &secure_column_name.to_string()).unwrap();

    Ok(e)

} 