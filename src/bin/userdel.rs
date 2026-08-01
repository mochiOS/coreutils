use std::io;

fn main() -> io::Result<()> {
    coreutils::user_management::require_root()?;
    let (name, remove_home) = parse_options()?;
    let mut database = coreutils::user_management::load_database()?;
    let user = database
        .remove(&name)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    coreutils::user_management::save_database(&database)?;
    if remove_home {
        coreutils::user_management::remove_home(&user)?;
    }
    println!("removed user {} uid={}", user.name, user.uid);
    Ok(())
}

fn parse_options() -> io::Result<(String, bool)> {
    let mut name = None;
    let mut remove_home = false;
    for argument in coreutils::args() {
        let argument = argument
            .into_string()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "arguments must be UTF-8"))?;
        match argument.as_str() {
            "--remove-home" => remove_home = true,
            value if value.starts_with('-') => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown option: {value}"),
                ));
            }
            value if name.is_none() => name = Some(value.to_string()),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "only one user name may be specified",
                ));
            }
        }
    }
    let Some(name) = name else {
        coreutils::usage("userdel", "[--remove-home] USER");
    };
    Ok((name, remove_home))
}
