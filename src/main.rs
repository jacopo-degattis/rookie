mod rookie;
pub use rookie::Rookie;

fn main() -> Result<(), std::io::Error> {
    let r = Rookie::new();
    let cookies = r.chrome_cookies("https://www.youtube.com", "Chrome").unwrap();
    println!("{:?}", cookies);

    Ok(())
}
