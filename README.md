# Cookie Extractor

## Description

A rust utility to extract encrypted cookies from Chrome. More browsers support will come.

## Usage

**First import rookie library**

```
mod rookie;
pub use rookie::Rookie;
```

**Then instantiate a rookie object**

```
let rk = Rookie::new();
```

**Last but not least call chrome_cookies method**

```
let cookies = r.chrome_cookies(<url:&str>, <browser:&str>).unwrap();
```

## Here's an example

```
mod rookie;
pub use rookie::Rookie;

fn main() -> Result<(), std::io::Error> {
    let r = Rookie::new();
    let cookies = r.chrome_cookies("https://www.youtube.com", "Chrome").unwrap();
    println!("{:?}", cookies);

    Ok(())
}

```

## Author

Jacopo De Gattis - (liljackx0@gmail.com)
