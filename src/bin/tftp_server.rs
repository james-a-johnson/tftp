use clap::Parser;
use daemonize::Daemonize;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use tftp::ServerBuilder;

#[derive(Parser)]
#[command(name = "tftp_server")]
#[command(author = "James Johnson")]
#[command(version = "1.0")]
struct TFTP {
    /// Directory to serve files from
    directory: String,
    /// IP address to bind to
    #[arg(short, long)]
    address: Option<IpAddr>,
    /// Port to bind to
    #[arg(short, long)]
    port: Option<u16>,
    /// Daemonize the server and run it in the background
    #[arg(long)]
    daemon: bool,
}

fn main() -> anyhow::Result<()> {
    let opts = TFTP::parse();
    let path = PathBuf::from(opts.directory);
    let server = ServerBuilder::new()
                                    .address(opts.address.unwrap_or(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))))
                                    .serve_dir(path)
                                    .port(opts.port.unwrap_or(69))
                                    .create()?;
    if opts.daemon {
        Daemonize::new()
            .pid_file("/tmp/tftp_server.pid")
            .start()?;
    }
    server.listen();
}