use std::io;

use mochios_user_database::{FIRST_REGULAR_UID, UserRecord};

struct Options {
    name: String,
    uid: Option<u32>,
    gid: Option<u32>,
    display_name: Option<String>,
    shell: Option<String>,
    create_home: bool,
}

fn main() -> io::Result<()> {
    coreutils::user_management::require_root()?;
    let options = parse_options()?;
    let database = coreutils::user_management::load_database()?;
    let uid = options
        .uid
        .unwrap_or(database.next_regular_uid().map_err(invalid_data)?);
    if uid < FIRST_REGULAR_UID {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "regular user ID must be at least 1000",
        ));
    }
    let gid = options.gid.unwrap_or(uid);
    let mut user = UserRecord::regular(&options.name, uid, gid);
    if let Some(display_name) = options.display_name {
        user.display_name = display_name;
    }
    if let Some(shell) = options.shell {
        user.shell = shell;
    }
    user.validate().map_err(invalid_data)?;
    let mut validated = database;
    validated.add(user.clone()).map_err(invalid_data)?;
    if options.create_home {
        coreutils::user_management::create_home(&user)?;
    }
    coreutils::user_management::add_user(user.clone())?;
    println!(
        "created user {} uid={} gid={} home={} locked=yes",
        user.name, user.uid, user.gid, user.home
    );
    Ok(())
}

fn parse_options() -> io::Result<Options> {
    let args = coreutils::args()
        .into_iter()
        .map(|arg| {
            arg.into_string()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "arguments must be UTF-8"))
        })
        .collect::<io::Result<Vec<_>>>()?;
    let mut uid = None;
    let mut gid = None;
    let mut display_name = None;
    let mut shell = None;
    let mut create_home = true;
    let mut name = None;
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--uid" | "--gid" | "--display-name" | "--shell" => {
                let option = args[index].as_str();
                index += 1;
                let value = args.get(index).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "option value is missing")
                })?;
                match option {
                    "--uid" => uid = Some(parse_id(value, "uid")?),
                    "--gid" => gid = Some(parse_id(value, "gid")?),
                    "--display-name" => display_name = Some(value.clone()),
                    "--shell" => shell = Some(value.clone()),
                    _ => unreachable!(),
                }
            }
            "--no-create-home" => create_home = false,
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
        index += 1;
    }
    let Some(name) = name else {
        coreutils::usage(
            "useradd",
            "[--uid ID] [--gid ID] [--display-name NAME] [--shell PATH] [--no-create-home] USER",
        );
    };
    Ok(Options {
        name,
        uid,
        gid,
        display_name,
        shell,
        create_home,
    })
}

fn parse_id(value: &str, field: &str) -> io::Result<u32> {
    value.parse::<u32>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid {field}: {value}"),
        )
    })
}

fn invalid_data(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}
