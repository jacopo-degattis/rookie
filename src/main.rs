mod rookie;
use std::env;
pub use rookie::Rookie;
use std::io::{Error, ErrorKind};
use url::{Url};

fn main() -> Result<(), std::io::Error> {

    let r = Rookie::new();
    let args: Vec<String> = env::args().collect();

    // Chromium is supported ? Check # TODO
    // let supported_browsers = vec!["Chrome", "Chromium"];
    let supported_browsers = vec!["Chrome"];

    // 1 because program name is included
    if args.len() == 1 {
        // JUST EXECUTE EXAMPLE CODE
        let cookies = r.chrome_cookies("https://www.netflix.com", "Chrome").unwrap();
        println!("{:?}", cookies);
    } else if args.len() > 1 {
        // INVALID ARGS WILL BE IGNORED ( RIGHT ? ) -> IMPROVE ?
        let valid_args: Vec<String> = args[1..args.len()].to_vec();
        
        if valid_args.len() > 2 {
            return Err(
                Error::new(
                    ErrorKind::InvalidInput,
                    "ERROR: wrong parameters, usage: ./rookie <uri> <browser:chrome>"
                )
            );
        }

        if let Err(_) = Url::parse(&valid_args[0]) {
            println!("{}", "Invalid URI has been provided");
        };

        if !supported_browsers.contains(&valid_args[1].as_str()) {
            // Add more browsers later
            println!("{}", "ERROR: browser is not supported, you must use either Chrome or Chromium");
        }

        let cookies = r.chrome_cookies(&valid_args[0], &valid_args[1]).unwrap();
        println!("{:?}", cookies);
    }

    Ok(())
}
