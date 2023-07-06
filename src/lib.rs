use std::env::current_dir;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::net::UdpSocket;
use std::os::unix::prelude::FileExt;
use std::path::PathBuf;
use std::thread::spawn;
use std::fs::OpenOptions;
use std::time::Duration;

mod error;
mod message;

pub use error::Error;
use message::{Mode, Message};

const TFTP_SERVE_PORT: u16 = 69;
const TFTP_BLOCK_SIZE: usize = 512;

macro_rules! send {
    ($socket:ident, $data:expr) => {
        if $socket.send($data).is_err() {
            eprintln!("ERROR: Failed to send response in {} at {}", file!(), line!());
        }
    }
}

pub struct ServerBuilder {
    address: Option<IpAddr>,
    port: Option<u16>,
    serve_dir: Option<PathBuf>,
    timeout: Option<Duration>,
}

impl ServerBuilder {
    pub fn new() -> Self {
        Self {
            address: None,
            port: None,
            serve_dir: None,
            timeout: None,
        }
    }

    pub fn address(self, addr: IpAddr) -> Self {
        Self {
            address: Some(addr),
            port: self.port,
            serve_dir: self.serve_dir,
            timeout: self.timeout,
        }
    }

    pub fn port(self, port: u16) -> Self {
        Self {
            address: self.address,
            port: Some(port),
            serve_dir: self.serve_dir,
            timeout: self.timeout,
        }
    }

    pub fn serve_dir(self, path: PathBuf) -> Self {
        Self {
            address: self.address,
            port: self.port,
            serve_dir: Some(path),
            timeout: self.timeout,
        }
    }

    pub fn timeout(self, time: Duration) -> Self {
        Self {
            address: self.address,
            port: self.port,
            serve_dir: self.serve_dir,
            timeout: Some(time),
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
        let timeout = self.timeout.unwrap_or(Duration::new(10, 0));
        socket.set_read_timeout(Some(timeout))?;
        socket.set_write_timeout(Some(timeout))?;
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
        let local_addr = self.socket.local_addr().expect("Couldn't get bound address").ip();
        loop {
            match self.socket.recv_from(&mut conn_buffer) {
                Ok((s, addr)) => {
                    let message = conn_buffer[..s].to_vec();
                    let dir = self.directory.clone();
                    spawn(move || {
                        handle_connection(local_addr.clone(), addr, message, dir);
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

fn handle_connection(host_addr: IpAddr, addr: SocketAddr, data: Vec<u8>, base_path: PathBuf) {
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
    let request = Message::try_from_bytes(&data);
    match request {
        Ok(r) => {
            match r {
                Message::Request { read, filename, mode } => {
                    if mode == Mode::Mail {
                        eprintln!("INFO: Got unsupported request for mail mode");
                        let unsupported = Message::Error { kind: Error::Illegal, msg: "Mail mode is unsupported".into() };
                        send!(conn_sock, &unsupported.to_vec());
                        return;
                    }
                    let filepath = base_path.join(filename);
                    if filepath < base_path {
                        // Trying to access a parent directory
                        // Send back an access violation
                        let access = Message::Error { kind: Error::AccessViolation, msg: "Can't access anything in a parent directory".into() };
                        send!(conn_sock, &access.to_vec());
                    } else {
                        let exists = filepath.try_exists().unwrap_or(false);
                        if filepath.is_dir() {
                            let directory = Message::Error { kind: Error::AccessViolation, msg: "Can't read or write a directory".into() };
                            send!(conn_sock, &directory.to_vec());
                            return;
                        }
                        match (read, exists) {
                            (true, true) => handle_read_request(conn_sock, filepath),
                            (false, _) => handle_write_request(conn_sock, filepath),
                            (_, _) => {
                                let exist = Message::Error { kind: Error::NotFound, msg: "File does not exist".into() };
                                send!(conn_sock, &exist.to_vec());
                            },
                        }
                    }
                },
                _ => {
                    let error = Message::Error { kind: Error::Illegal, msg: "Initial message must be a read or write request".into() };
                    send!(conn_sock, &error.to_vec());
                }
            }
        },
        Err(r) => {
            eprintln!("ERROR: Received an invalid initial request");
            send!(conn_sock, &r.to_vec());
        }
    }
}

fn handle_read_request(conn: UdpSocket, filename: PathBuf) {
    let mut read_buffer = [0u8; TFTP_BLOCK_SIZE];
    let mut block: u16 = 0;
    let file = OpenOptions::new()
        .read(true)
        .write(false)
        .create(false)
        .open(filename.clone());
    let file = match file {
        Ok(f) => f,
        Err(_) => {
            let open = Message::Error { kind: Error::AccessViolation, msg: "Couldn't open file".into() };
            send!(conn, &open.to_vec());
            eprintln!("ERROR: Failed to open file {}", filename.display());
            return;
        }
    };
    'read_loop: loop {
        let file_read = file.read_at(&mut read_buffer, (TFTP_BLOCK_SIZE * (block as usize)) as u64);
        match file_read {
            Ok(r) => {
                let data = Message::Data { block, data: read_buffer[..r].to_vec() };
                let send = conn.send(&data.to_vec());
                match send {
                    Ok(_) => {},
                    Err(e) => {
                        match e.kind() {
                            std::io::ErrorKind::Interrupted => continue 'read_loop,
                            _ => {
                                // I don't think any other error is recoverable so just return
                                eprintln!("ERROR: Connection failed with {}", e);
                                return;
                            }
                        }
                    },
                }
            },
            Err(e) => {
                
            }
        }
    }
}

fn handle_write_request(conn: UdpSocket, filename: PathBuf) {}
