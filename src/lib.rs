//! Simple TFTP Server
//!
//! Use the [`ServerBuilder`] to create a [`Server`] which can handle read and write requests.
//!
//! This implementation is most likely not fully compliant with the RFC. The goal was to just make
//! something simple and easy to use that would work for most cases.
//!
//! This library makes the choice to not be lentient with any errors. When any error occurs, this library
//! will most likely just print that an error occurred and either send an error to the client and close the
//! connection or just assume the network connection has failed in some way and close the connection.
//!
//! [`Server`] will use threads to handle each connection as they come in. There is no maximum number of
//! threads parameter so a system could run out of resources if enough connections are made at the same
//! time.
//!
//! # Security
//! This library provides no security guarantees at all. It does only the very basics to prevent any
//! directory traversal attacks. As one security measure, this library **will not overwrite any existing
//! files on disk**.
//!
//! **Do not use this library as a public facing TFTP server**.

use std::env::current_dir;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::UdpSocket;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::prelude::FileExt;
use std::path::PathBuf;
use std::thread::spawn;
use std::time::Duration;

mod error;
mod message;

use error::Error;
use message::{Message, Mode};

/// Default TFTP port server port
const TFTP_SERVE_PORT: u16 = 69;
/// Size of TFTP data block
const TFTP_BLOCK_SIZE: usize = 512;
/// Number of times to retry sending data or an ack
const NUM_RETIRES: usize = 3;

/// Macro for sending a packet and printing an error if it fails
macro_rules! send {
    ($socket:ident, $data:expr) => {
        if $socket.send($data).is_err() {
            eprintln!(
                "ERROR: Failed to send response in {} at {}",
                file!(),
                line!()
            );
        }
    };
}

/// Builder struct for creating a TFTP server
///
/// Currently this is the only way to create a TFTP server. It can be used to set each of the
/// settings of a TFTP server. The settings are
///  - IP address to listen on (v4 or v6)
///  - Port to listen on
///  - Directory to serve data out of
///  - Timeout for reading and writing to the socket
///
/// If none of the settings are explicitly set, default values will be used for each.
/// See the respective methods for the default value.
///
/// # Example
/// ```
/// let server = ServerBuilder::new()
///                 .serve_dir("/srv/tftp")
///                 .address([127, 0 ,0, 1])
///                 .port(4321)
///                 .create().unwrap();
/// server.listen();
/// ```
pub struct ServerBuilder {
    address: Option<IpAddr>,
    port: Option<u16>,
    serve_dir: Option<PathBuf>,
    timeout: Option<Duration>,
}

impl ServerBuilder {
    /// Create a new builder with all default values
    pub fn new() -> Self {
        Self {
            address: None,
            port: None,
            serve_dir: None,
            timeout: None,
        }
    }

    /// Set the IP address on which the server will listen
    ///
    /// The default address to listen on is [`std::net::Ipv4Addr::UNSPECIFIED`].
    ///
    /// # Arguments
    ///  - addr: IP address to which the listening UDP socket will be bound
    ///
    /// # Example
    /// ```
    /// # use std::net::Ipv4Addr;
    /// let server = ServerBuilder::new()
    ///                 .address(Ipv4Addr::new(0, 0, 0, 0))
    ///                 .create().unwrap();
    /// server.listen();
    /// ```
    pub fn address(self, addr: impl Into<IpAddr>) -> Self {
        Self {
            address: Some(addr.into()),
            port: self.port,
            serve_dir: self.serve_dir,
            timeout: self.timeout,
        }
    }

    /// Set the port on which the server will listen
    ///
    /// Default port is 69 as specified in the TFTP rfc.
    ///
    /// # Arguments
    ///  - port: Port on which to bind listening UDP socket
    ///
    /// # Example
    /// ```
    /// let server = ServerBuilder::new()
    ///                 .port(3232)
    ///                 .create().unwrap();
    /// server.listen();
    /// ```
    pub fn port(self, port: u16) -> Self {
        Self {
            address: self.address,
            port: Some(port),
            serve_dir: self.serve_dir,
            timeout: self.timeout,
        }
    }

    /// Set directory to serve files from
    ///
    /// Default directory is the one from which the executable was started.
    ///
    /// # Arguments
    /// - path: Path from which to allow reading and writing of files
    ///
    /// # Example
    /// ```
    /// let server = ServerBuilder::new()
    ///                 .serve_dir("/var/www")
    ///                 .create().unwrap();
    /// server.listen();
    /// ```
    pub fn serve_dir(self, path: impl Into<PathBuf>) -> Self {
        Self {
            address: self.address,
            port: self.port,
            serve_dir: Some(path.into()),
            timeout: self.timeout,
        }
    }

    /// Set the timeout duration for reading and writing to the network
    ///
    /// Default duration is 10 seconds.
    ///
    /// # Arguments
    ///  - time: Timeout duration
    ///
    /// # Example
    /// ```
    /// # use std::time::Duration
    /// let server = ServerBuilder::new()
    ///                 .timeout(Duration::new(1, 0))
    ///                 .create().unwrap();
    /// server.listen();
    /// ```
    pub fn timeout(self, time: Duration) -> Self {
        Self {
            address: self.address,
            port: self.port,
            serve_dir: self.serve_dir,
            timeout: Some(time),
        }
    }

    /// Create new [`Server`] from given options
    ///
    /// # Errors
    /// Creating the server can fail at a couple of points:
    ///  - The directory from which to serve files does not exist
    ///  - Creating a UDP socket failed
    ///  - Setting the read or write timeout failed
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

/// TFTP server
///
/// Handles reading and writing of files from the set serve directory.
///
/// # Security
/// This implementation does not make any strong security guarantees. It does attempt to ensure that any file that
/// is read or written is within the set serve directory. However, this is not guaranteed. The only check is to
/// make sure that the path requested from the user appended to the serve directory is still a subdirectory of the
/// serve directory.
pub struct Server {
    socket: UdpSocket,
    directory: PathBuf,
}

impl Server {
    /// Start listening for connections
    ///
    /// This function will block the thread of execution and never return.
    ///
    /// For each connection made, a new thread will be spawned to handle that connection.
    pub fn listen(self) -> ! {
        let mut conn_buffer = [0u8; 1024];
        let local_addr = self
            .socket
            .local_addr()
            .expect("Couldn't get bound address")
            .ip();
        loop {
            match self.socket.recv_from(&mut conn_buffer) {
                Ok((s, addr)) => {
                    let message = conn_buffer[..s].to_vec();
                    let dir = self.directory.clone();
                    spawn(move || {
                        handle_connection(local_addr.clone(), addr, message, dir);
                    });
                }
                Err(e) => match e.kind() {
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => continue,
                    _ => {
                        eprintln!("ERROR: Trying to read from new connection");
                        eprintln!("ERROR: {e:?}");
                        continue;
                    }
                },
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

/// Handle a new incoming connection
///
/// This function will create a new socket to handle the connection with a random port number.
///
/// # Arguments
///  - host_addr: IP address that should be used by the server to bind the UDP port to
///  - addr: Address of the clients socket
///  - data: The initial request data
///  - base_path: Path of the serve directory
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
                Message::Request {
                    read,
                    filename,
                    mode,
                } => {
                    if mode == Mode::Mail {
                        eprintln!("INFO: Got unsupported request for mail mode");
                        let unsupported = Message::Error {
                            kind: Error::Illegal,
                            msg: "Mail mode is unsupported".into(),
                        };
                        send!(conn_sock, &unsupported.to_vec());
                        return;
                    }
                    let filepath = base_path.join(filename);
                    if filepath < base_path {
                        // Trying to access a parent directory
                        // Send back an access violation
                        let access = Message::Error {
                            kind: Error::AccessViolation,
                            msg: "Can't access anything in a parent directory".into(),
                        };
                        send!(conn_sock, &access.to_vec());
                    } else {
                        let exists = filepath.try_exists().unwrap_or(false);
                        if filepath.is_dir() {
                            let directory = Message::Error {
                                kind: Error::AccessViolation,
                                msg: "Can't read or write a directory".into(),
                            };
                            send!(conn_sock, &directory.to_vec());
                            return;
                        }
                        match (read, exists) {
                            (true, true) => handle_read_request(conn_sock, filepath),
                            (false, _) => handle_write_request(conn_sock, filepath),
                            (_, _) => {
                                let exist = Message::Error {
                                    kind: Error::NotFound,
                                    msg: "File does not exist".into(),
                                };
                                send!(conn_sock, &exist.to_vec());
                            }
                        }
                    }
                }
                _ => {
                    let error = Message::Error {
                        kind: Error::Illegal,
                        msg: "Initial message must be a read or write request".into(),
                    };
                    send!(conn_sock, &error.to_vec());
                }
            }
        }
        Err(r) => {
            eprintln!("ERROR: Received an invalid initial request");
            send!(conn_sock, &r.to_vec());
        }
    }
}

/// Handles a client reading a file
///
/// # Arguments
///  - conn: Socket with which to communicate with the client
///  - filename: Path of the file to send to the client
fn handle_read_request(conn: UdpSocket, filename: PathBuf) {
    eprintln!("INFO: Sending file {:?}", filename);
    let mut read_buffer = [0u8; TFTP_BLOCK_SIZE];
    let mut receive_buffer = [0u8; 2 * TFTP_BLOCK_SIZE];
    let mut block: u16 = 1;
    let mut last = false;
    let mut ack_attempts = 0;
    let file = OpenOptions::new()
        .read(true)
        .write(false)
        .create(false)
        .open(filename.clone());
    let file = match file {
        Ok(f) => f,
        Err(_) => {
            let open = Message::Error {
                kind: Error::AccessViolation,
                msg: "Couldn't open file".into(),
            };
            send!(conn, &open.to_vec());
            eprintln!("ERROR: Failed to open file {}", filename.display());
            return;
        }
    };
    'read_loop: loop {
        let file_read = file.read_at(
            &mut read_buffer,
            (TFTP_BLOCK_SIZE * ((block - 1) as usize)) as u64,
        );
        match file_read {
            Ok(r) => {
                let data = Message::Data {
                    block,
                    data: read_buffer[..r].to_vec(),
                };
                let msg = data.to_vec();
                let send = conn.send(&msg);
                if r < TFTP_BLOCK_SIZE {
                    last = true;
                }
                match send {
                    Ok(s) => {
                        if s != msg.len() {
                            // Unable to send all of the message
                            // Assume connection is bad and exit
                            eprintln!("ERROR: Failed to send whole message");
                            break 'read_loop;
                        }
                    }
                    Err(e) => {
                        match e.kind() {
                            std::io::ErrorKind::Interrupted => continue 'read_loop,
                            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
                                continue 'read_loop
                            }
                            _ => {
                                // I don't think any other error is recoverable so just return
                                eprintln!("ERROR: Connection failed with {}", e);
                                return;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("ERROR: Failed to read file with {:?}", e);
                let data = Message::Error {
                    kind: Error::Undefined,
                    msg: "Failed to read file".into(),
                };
                send!(conn, &data.to_vec());
                break 'read_loop;
            }
        }

        ack_attempts += 1;
        if ack_attempts > NUM_RETIRES {
            eprintln!("ERROR: Connection dropped");
            break 'read_loop;
        }
        match conn.recv(&mut receive_buffer) {
            Ok(s) => match Message::try_from_bytes(&receive_buffer[..s]) {
                Ok(m) => match m {
                    Message::Ack { block: b } => {
                        if b == block {
                            block += 1;
                            ack_attempts = 0;
                            if last {
                                break 'read_loop;
                            }
                        } else {
                            continue 'read_loop;
                        }
                    }
                    m @ Message::Error { .. } => {
                        eprintln!("ERROR: Received invalid message {:?}", m);
                        break 'read_loop;
                    }
                    _ => {
                        let invalid = Message::Error {
                            kind: Error::Illegal,
                            msg: "Illegal message type".into(),
                        };
                        send!(conn, &invalid.to_vec());
                        break 'read_loop;
                    }
                },
                Err(error_msg) => {
                    eprintln!("ERROR: Failed to parse message from client {:?}", error_msg);
                    send!(conn, &error_msg.to_vec());
                    break 'read_loop;
                }
            },
            Err(io_err) => match io_err.kind() {
                std::io::ErrorKind::Interrupted => continue 'read_loop,
                std::io::ErrorKind::TimedOut => {
                    ack_attempts += 1;
                    continue 'read_loop;
                }
                _ => {
                    eprintln!("ERROR: Connection dropped");
                    break 'read_loop;
                }
            },
        }
    }
    eprintln!("INFO: Finished sending file");
}

/// Handles a client writing a file
///
/// # Arguments
///  - conn: Socket with which to communicate with the client
///  - filename: Path of the file the client is uploading
fn handle_write_request(conn: UdpSocket, filename: PathBuf) {
    eprintln!("INFO: Receiving file {:?}", filename);
    let mut receive_buffer = [0u8; 2 * TFTP_BLOCK_SIZE];
    let mut block: u16 = 0;
    let mut read_attempts = 0;
    let file = OpenOptions::new()
        .read(false)
        .write(true)
        .create_new(true)
        .open(filename.clone());
    let mut file = match file {
        Ok(f) => f,
        Err(_) => {
            let open = Message::Error {
                kind: Error::AccessViolation,
                msg: "Couldn't open file".into(),
            };
            send!(conn, &open.to_vec());
            eprintln!("ERROR: Failed to open file {}", filename.display());
            return;
        }
    };
    // Send initial ack
    let initial_ack = Message::Ack { block };
    match conn.send(&initial_ack.to_vec()) {
        Ok(_) => block += 1,
        Err(_) => {
            drop(file);
            if std::fs::remove_file(filename).is_err() {
                eprintln!("ERROR: Failed to remove empty file");
            }
            return;
        }
    }
    'write_loop: loop {
        read_attempts += 1;
        if read_attempts > NUM_RETIRES {
            eprintln!("ERROR: Connection dropped");
            break 'write_loop;
        }
        match conn.recv(&mut receive_buffer) {
            Ok(s) => match Message::try_from_bytes(&receive_buffer[..s]) {
                Ok(m) => match m {
                    Message::Data {
                        block: b,
                        data: file_data,
                    } => {
                        if b == block {
                            read_attempts = 0;
                            match file.write_all(&file_data) {
                                Ok(()) => {
                                    block += 1;
                                    let ack = Message::Ack { block: block - 1 };
                                    match conn.send(&ack.to_vec()) {
                                        Ok(_) => {
                                            block += 1;
                                            if file_data.len() < TFTP_BLOCK_SIZE {
                                                break 'write_loop;
                                            }
                                            continue 'write_loop;
                                        }
                                        Err(_) => {
                                            eprintln!("ERROR: Connection dropped");
                                            break 'write_loop;
                                        }
                                    }
                                }
                                Err(e) => {
                                    eprintln!("ERROR: Failed to write to file {:?}", e);
                                    let err_resp = Message::Error {
                                        kind: Error::Undefined,
                                        msg: "Failed to write file".into(),
                                    };
                                    send!(conn, &err_resp.to_vec());
                                    break 'write_loop;
                                }
                            }
                        } else {
                            continue 'write_loop;
                        }
                    }
                    m @ Message::Error { .. } => {
                        eprintln!("ERROR: Received error message {:?}", m);
                        break 'write_loop;
                    }
                    _ => {
                        let invalid = Message::Error {
                            kind: Error::Illegal,
                            msg: "Illegal message type".into(),
                        };
                        send!(conn, &invalid.to_vec());
                        break 'write_loop;
                    }
                },
                Err(error_msg) => {
                    eprintln!("ERROR: Failed to parse message from client {:?}", error_msg);
                    send!(conn, &error_msg.to_vec());
                    break 'write_loop;
                }
            },
            Err(io_err) => match io_err.kind() {
                std::io::ErrorKind::Interrupted => continue 'write_loop,
                std::io::ErrorKind::TimedOut => {
                    read_attempts += 1;
                    continue 'write_loop;
                }
                _ => {
                    eprintln!("ERROR: Connection dropped");
                    break 'write_loop;
                }
            },
        }
    }
    eprintln!("INFO: Finished writing file");
}
