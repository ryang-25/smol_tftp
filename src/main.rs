// An example client application

#[cfg(feature = "std")]
use smol_tftp::{client::StdClient, error::Result};
#[cfg(feature = "std")]
use std::os::unix::ffi::OsStrExt;
#[cfg(feature = "std")]
use std::{env, ffi::CString, fs::File, path::Path};

#[cfg(feature = "std")]
fn main() -> Result<()> {
    // Bind to any.
    let bind_addr = "0.0.0.0:0";

    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        todo!();
    }
    let server_addr = &args[1];
    let path = Path::new(&args[3]);
    let file_name = path.file_name().unwrap();

    let mut client = StdClient::new(bind_addr.parse().unwrap(), server_addr.parse().unwrap())?;
    match args[2].as_str() {
        "read" => {
            let mut f = File::create(path)?;
            client.receive_file(&CString::new(file_name.as_bytes())?, c"binary", &mut f)?
        }
        "write" => client.send_file(path, c"binary")?,
        _ => todo!(),
    };
    Ok(())
}

#[cfg(not(feature = "std"))]
fn main() {}
