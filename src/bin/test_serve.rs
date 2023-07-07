use tftp::ServerBuilder;
use std::path::PathBuf;
use std::net::{IpAddr, Ipv4Addr};

fn main() -> Result<(), Box<(dyn std::error::Error + 'static)>> {
    let server = ServerBuilder::new()
        .address(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
        .serve_dir(PathBuf::from("."))
        .port(1654)
        .create()?;
    server.listen();
}