# Cookie Extractor

## Description

A rust utility to extract encrypted cookies from Chrome. More browsers support will come.

## CLI Usage

**First compile the project**

```console
$ cargo build
```

**Install and/or execute from target folder**

Now you can either install the program in your system (it will be located in /usr/local/bin/) or you can execute it without installation.

### Install in your system

```console
$ ./install.sh
rookie <url> <browser_name>

N.B: if you exec rookie without parameters example code will run. You can find example code in "main.rs" file of this project.
```

### Executing from local target folder

```console
$ cd src/target/
$ ./rookie <url> <browser_name>
```

## Library Usage

**First import rookie library**

```rust
mod rookie;
pub use rookie::Rookie;
```

**Then instantiate a rookie object**

```rust
let rk = Rookie::new();
```

**Last but not least call chrome_cookies method**

```rust
let cookies = r.chrome_cookies(<url:&str>, <browser:&str>).unwrap();
```

### Here's an example

```rust
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
