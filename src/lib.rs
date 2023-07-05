use std::env::current_dir;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::net::{ToSocketAddrs, UdpSocket};
use std::path::PathBuf;
use std::thread::spawn;

mod error;
mod message;

pub use error::Error;

const TFTP_SERVE_PORT: u16 = 69;
const TFTP_BLOCK_SIZE: usize = 512;

pub struct ServerBuilder {
    address: Option<IpAddr>,
    port: Option<u16>,
    serve_dir: Option<PathBuf>,
}

impl ServerBuilder {
    pub fn new() -> Self {
        Self {
            address: None,
            port: None,
            serve_dir: None,
        }
    }

    pub fn address(self, addr: IpAddr) -> Self {
        Self {
            address: Some(addr),
            port: self.port,
            serve_dir: self.serve_dir,
        }
    }

    pub fn port(self, port: u16) -> Self {
        Self {
            address: self.address,
            port: Some(port),
            serve_dir: self.serve_dir,
        }
    }

    pub fn serve_dir(self, path: PathBuf) -> Self {
        Self {
            address: self.address,
            port: self.port,
            serve_dir: Some(path),
        }
    }

    pub fn create(self) -> std::io::Result<Server> {
        let dir = self.serve_dir.unwrap_or(current_dir()?);
        if !dir.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                Error::NotFound,
            ));
        }
        let socket = UdpSocket::bind((
            self.address.unwrap_or(Ipv4Addr::UNSPECIFIED.into()),
            self.port.unwrap_or(TFTP_SERVE_PORT),
        ))?;
        Ok(Server {
            socket,
            directory: dir,
        })
    }
}

pub struct Server {
    socket: UdpSocket,
    directory: PathBuf,
}

impl Server {
    pub fn listen(self) -> ! {
        let mut conn_buffer = [0u8; 1024];
        loop {
            match self.socket.recv_from(&mut conn_buffer) {
                Ok((s, addr)) => {
                    let message = &conn_buffer[..s];
                    spawn(move || {
                        handle_connection(addr, message.to_vec());
                    });
                }
                Err(e) => {
                    eprintln!("ERROR: Trying to read from new connection");
                    eprintln!("ERROR: {e:?}");
                    continue;
                }
            }
        }
    }
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TFTPServer")
            .field("Address", &self.socket.local_addr().unwrap())
            .field("Directory", &self.directory.display())
            .finish()
    }
}

fn handle_connection(host_addr: IpAddr, addr: SocketAddr, data: Vec<u8>) {
    eprintln!("INFO: Got a connection from {addr:?}");
    // First get a udp socket to use. This will be used for sending back an error or for the rest of
    // the connection if everything goes well
    // Asking for port zero will tell the kernel to assign a random unused to the socket
    let conn_sock = UdpSocket::bind((host_addr, 0));
    if conn_sock.is_err() {
        // Impossible to send a error response so just return
        eprintln!("ERROR: Unable to open a udp socket to respond to request");
        return;
    }
    let conn_sock = conn_sock.unwrap();
    if conn_sock.connect(addr).is_err() {
        eprintln!("ERROR: Failed to connect to {addr:?}");
        return;
    }
    if data.len() < 4 {
        eprintln!("ERROR: Received message with less than 4 bytes");
        let error_response = ErrorMsg {
            kind: Error::Undefined,
            msg: "Request must be at least 4 bytes",
        };
        conn_sock.send(&error_response.to_bytes());
        return;
    }
    let op = u16::from_be_bytes(data[..2].try_into().unwrap());
    let op = Operation::try_from(op);
    let op = match op {
        Ok(o) => o,
        Err(_) => {
            let error_response = ErrorMsg {
                kind: Error::Undefined,
                msg: "Undefined operation",
            };
            conn_sock.send(&error_response.to_bytes());
            return;
        }
    };
    match op {
        Operation::Rrq => handle_read_request(conn_sock, &data[2..]),
        Operation::Wrq => handle_write_request(conn_sock, &data[2..]),
        _ => {
            let error_response = ErrorMsg {
                kind: Error::Illegal,
                msg: "Invalid initial operation",
            };
            conn_sock.send(&error_response.to_bytes());
        }
    }
}

fn handle_read_request(conn: UdpSocket, req: &[u8]) {}

fn handle_write_request(conn: UdpSocket, req: &[u8]) {}
