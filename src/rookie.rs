use std::str;
use aes::Aes128;
extern crate dirs;
extern crate keyring;
extern crate urlparse;
use urlparse::urlparse;
use std::convert::TryFrom;
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use openssl::pkcs5::pbkdf2_hmac;
use openssl::hash::MessageDigest;
use block_modes::{BlockMode, Cbc};
use rusqlite::{Connection, Result};
use block_modes::block_padding::Pkcs7;


#[derive(Debug)]
#[allow(dead_code)]
struct TableInfo {
    sl_no: i32,
    column_name: String,
    data_type: String,
    is_null: i32,
    default_val: Option<String>,
    pk: i32,
}


#[derive(Debug)]
#[allow(dead_code)]
struct Cooky {
    hk: String,
    path: String,
    is_secure: bool,
    expires_utc: i64,
    cookie_key: String,
    val: Option<String>,
    enc_val:  Vec<u8>
}

type Aes128Cbc = Cbc<Aes128, Pkcs7>;

#[allow(dead_code)]
pub struct Rookie {
    cookie_path: String
}

// TODO: optimize parameters, exploiting class struct

impl Rookie {

    pub fn new() -> Self {
        Rookie {
            cookie_path: String::from("Google/Chrome/Default/Cookies")
        }
    }

    fn _get_safe_storage_keyring(&self) -> Result<String, keyring::Error> {

        let keyring_entry = format!("{} Safe Storage", "Chrome");
        let entry = keyring::Entry::new(&keyring_entry, "Chrome");
        
        let password: String = match entry.get_password() {
            Ok(val) => val,
            Err(err) => format!("{}", err),
        };
    
        Ok(password)
    }

    fn _get_os_config(&self) -> Result<HashMap<&str, String>, Error> {
        /*
            Get settings to fetch chrome cookies based upon
            the currently using OS.

            Args:
                browser: "Chrome" | "Chromium"
            
            Returns:
                Config HashMap for cookies decryption
        */

        let mut config: HashMap<&str, String> = HashMap::new();

        // let browser_folding = HashMap::from([
        //     ("Chrome", "Google/Chrome"),
        //     ("Chromium", "Chromium")
        // ]);

        // if !vec!["Chrome", "Chromium"].contains(&browser) {
        //     return Err(
        //         Error::new(
        //             ErrorKind::InvalidInput,
        //             "Browser must be either 'Chrome' or 'Chromium'"
        //         )
        //     );
        // }

        let cookie_path = format!(
            // "~/Library/Application Support/{}/Default/Cookies",
            "~/Library/Application Support/{}/Default/Cookies",
            "Google/Chrome"
            // browser_folding[browser]
        );

        let password = self._get_safe_storage_keyring().unwrap();
        
        config.extend([
            ("psw", password),
            ("iterations", String::from("1003")),
            ("cookie_file", cookie_path)
        ]);

        Ok(config)
    }

    fn _fetch_cookie_table_info_from_db(
        &self,
        conn: &Connection,
    ) -> Result<Vec<TableInfo>, rusqlite::Error> {

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

        let infos: Vec<TableInfo> = cookies
                .map(|x| x.unwrap())
                .collect();
    
        Ok(infos)
    }

    fn _generate_host_keys(&self, hostname: &String) -> Result<Vec<String>, std::io::Error> {
        let labels = hostname.split(".");
        let vec: Vec<&str> = labels.collect();
        let mut entries: Vec<String> = Vec::new();

        for i in 2..vec.len() + 1 {
            let domain = vec[vec.len() - i .. vec.len()].join(".");
            let formatted = format!(".{}", domain.clone());
            entries.extend([domain, formatted]);
        }
        
        Ok(entries)
    }

    fn _chrome_decrypt(
        &self,
        enc_val: Vec<u8>,
        input_key: &[u8; 16],
        init_vector: &String
    ) -> Result<String, std::io::Error> {
        let encrypted_value: Vec<u8> = enc_val[3..enc_val.len()].to_vec();
        let mut test = encrypted_value; // TODO: improve, skip this statement

        let cipher = Aes128Cbc::new_from_slices(input_key, init_vector.as_bytes()).unwrap();
        let e = cipher.decrypt(&mut test).unwrap().to_vec();
        let utf_value = String::from_utf8(e).unwrap();

        Ok(utf_value)
    }

    fn _fetch_cookies_from_db(
        &self,
        conn: &Connection,
        domain: &String,
        secure_column_name: &String,
        salted_password: &[u8; 16],
        init_vector: &String
    ) -> Result<HashMap<String, String>, rusqlite::Error> {

        let keys = &self._generate_host_keys(domain).unwrap();
        let mut cookies_dump: HashMap<String, String> = HashMap::new();

        for host_key in keys {
    
            let mut query = conn.prepare(
                format!("select host_key, path, {}, expires_utc, name, value, encrypted_value from cookies where host_key like '{}'", secure_column_name, host_key).as_str(),
            )?;

            // NOTE: use external variable to store returned value ? like let ckies = 
            match query.query_map([], |row| {
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
                // TODO: improve error handling match and nesting
                Ok(val) => {
                    for c in val {
                        match c {
                            Ok(v) => {
                                let current_value = v.val.unwrap();
                                let version: &[u8] = &v.enc_val[0..3];
                                let is_valid = !vec!["v10".as_bytes(), "v11".as_bytes()].contains(&version);
                                
                                if &current_value.len() > &0 || is_valid {
                                    cookies_dump.extend([
                                        (v.cookie_key, current_value),
                                    ]);
                                } else {
                                    let current_value = &self._chrome_decrypt(
                                        v.enc_val,
                                        salted_password,
                                        init_vector
                                    ).unwrap();

                                    cookies_dump.extend([
                                        (v.cookie_key, String::from(current_value))
                                    ]);
                                }
                            },
                            Err(e) => println!("{:?}", e)
                        }
                    }
                },
                Err(err) => println!("err, {}", err)
            };
        }

        Ok(cookies_dump)
    }

    pub fn chrome_cookies(
        self,
        url: &str,
    ) -> Result<HashMap<String, String>, std::io::Error> {
        let mut config: HashMap<&str, String>;

        // TODO: add linux and windows support too
        if cfg!(target_os="macos") {
            config = self._get_os_config().unwrap();
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
            ("salt", String::from("saltysalt"))
        ]);

        let home_dir_str = dirs::home_dir().unwrap();
        let cookie_file = format!(
            "{}{}",
            home_dir_str.to_str().unwrap(),
            config["cookie_file"].replace("~", "")
        );

        let mut salted_password: [u8; 32] = [0; 32];
        
        match pbkdf2_hmac(
            config["psw"].as_bytes(),
            config["salt"].as_bytes(),
            config["iterations"].parse::<usize>().unwrap(),
            MessageDigest::sha1(),
            &mut salted_password
        ) {
            Ok(_) => String::from("ok"),
            Err(err) => format!("{}", err)
        };

        let byte_slice = &salted_password[0..16];
        let truncated_salted_password = <&[u8; 16]>::try_from(byte_slice).unwrap();

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

        let table_infos = self._fetch_cookie_table_info_from_db(&conn).unwrap();

        let mut secure_column_name = "";
        for info in table_infos {
            if info.column_name == "is_secure" {
                secure_column_name = "is_secure";
            }
        }

        let init_vector = &config["init_vector"];
        let cookies = self._fetch_cookies_from_db(
            &conn,
            &domain,
            &secure_column_name.to_string(),
            &truncated_salted_password,
            &init_vector
        ).unwrap();

        Ok(cookies)

    } 
}

// https://docs.rs/rusqlite/0.13.0/rusqlite/blob/index.html
// NOTE: move value, not implement trait copy fix:
// https://stackoverflow.com/questions/28800121/what-do-i-have-to-do-to-solve-a-use-of-moved-value-error
// TODO: remove #[allow(dead_code)] and use or remove unused variables