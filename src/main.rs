mod cookieext;

fn main() -> Result<(), std::io::Error> {
    // let value = cookieext::get_os_config("chrome");

    // match value {
    //     Ok(val) => println!("{:?}", val),
    //     Err(err) => return Err(err)
    // }
    let e = cookieext::chrome_cookies("https://www.instagram.com/", "Chrome").unwrap();
    println!("{:?}", e);

    Ok(())
}
