mod cookieext;
use std::io::Error;

fn main() -> Result<(), std::io::Error> {
    // let value = cookieext::get_os_config("chrome");

    // match value {
    //     Ok(val) => println!("{:?}", val),
    //     Err(err) => return Err(err)
    // }
    let _e = cookieext::chrome_cookies("https://www.instagram.com/", "Chrome");

    Ok(())
}
