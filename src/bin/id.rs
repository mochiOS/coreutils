use std::io;

fn main() -> io::Result<()> {
    let database = coreutils::user_management::load_database()?;
    let argument = coreutils::args().into_iter().next();
    let user = if let Some(argument) = argument {
        let name = argument
            .into_string()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "user name must be UTF-8"))?;
        database.find_name(&name)
    } else {
        let uid = unsafe { libc::getuid() };
        database.find_uid(uid)
    }
    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "user was not found"))?;

    println!(
        "uid={}({}) gid={} home={} shell={} locked={}",
        user.uid,
        user.name,
        user.gid,
        user.home,
        user.shell,
        if user.locked { "yes" } else { "no" }
    );
    Ok(())
}
