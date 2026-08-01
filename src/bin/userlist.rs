use std::io;

fn main() -> io::Result<()> {
    let database = coreutils::user_management::load_database()?;
    for user in database.users() {
        println!(
            "{}\tuid={}\tgid={}\thome={}\tshell={}\tlocked={}",
            user.name,
            user.uid,
            user.gid,
            user.home,
            user.shell,
            if user.locked { "yes" } else { "no" }
        );
    }
    Ok(())
}
