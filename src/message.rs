//! Implementation of parsing and encoding of message types for TFTP
//!
//! There are really only two important types from this package:
//! - [`Mode`]
//! - [`Message`]

use core::ffi::FromBytesUntilNulError;
use std::ffi::{CStr, NulError};
use std::path::PathBuf;

use crate::error::Error;

/// All of the valid TFTP operations
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
enum Operation {
    /// Read request
    Rrq = 1,
    /// Write request
    Wrq = 2,
    /// Data message
    Data = 3,
    /// Acknowledgement
    Ack = 4,
    /// Error message
    Error = 5,
}

impl std::convert::TryFrom<u16> for Operation {
    type Error = crate::Error;
    fn try_from(value: u16) -> Result<Self, crate::Error> {
        match value {
            1 => Ok(Operation::Rrq),
            2 => Ok(Operation::Wrq),
            3 => Ok(Operation::Data),
            4 => Ok(Operation::Ack),
            5 => Ok(Operation::Error),
            _ => Err(Error::Illegal),
        }
    }
}

/// All of the valid TFTP data modes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// Octet mode
    Octet,
    /// Net ascii mode
    NetAscii,
    /// Mail mode
    Mail,
}

impl Mode {
    pub(crate) fn to_str(&self) -> &'static [u8] {
        match *self {
            Mode::Octet => b"Octet\x00",
            Mode::NetAscii => b"NetAscii\x00",
            Mode::Mail => b"Mail\x00",
        }
    }
}

impl TryFrom<&str> for Mode {
    type Error = Message;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mode_str = value.to_ascii_lowercase();
        match mode_str.as_str() {
            "octet" => Ok(Self::Octet),
            "netascii" => Ok(Self::NetAscii),
            "mail" => Ok(Self::Mail),
            _ => Err(Message::Error {
                kind: Error::Undefined,
                msg: "Undefined mode string".into(),
            }),
        }
    }
}

/// All of the valid TFTP message types
#[derive(Debug)]
pub(crate) enum Message {
    /// Read or write request
    Request {
        /// Indicates if the request is to read a file or write a file
        ///
        /// True indicates reading and false indicates writing.
        read: bool,
        /// Path of the file to read or write
        filename: PathBuf,
        /// Mode in which the data will be sent
        mode: Mode,
    },
    /// Data message
    Data {
        /// Block number of the data
        block: u16,
        /// Data within data packet
        data: Vec<u8>,
    },
    /// Data acknowledgement
    Ack {
        /// Block number
        block: u16,
    },
    /// Error message
    Error {
        /// Type of error
        kind: Error,
        /// Error message associated with error
        msg: String,
    },
}

impl From<crate::error::Error> for Message {
    fn from(value: crate::error::Error) -> Self {
        Message::Error {
            kind: value,
            msg: format!("{:?}", value),
        }
    }
}

impl From<NulError> for Message {
    fn from(_value: NulError) -> Self {
        Message::Error {
            kind: Error::Undefined,
            msg: "Received invalid string".into(),
        }
    }
}

impl From<FromBytesUntilNulError> for Message {
    fn from(_value: FromBytesUntilNulError) -> Self {
        Message::Error {
            kind: Error::Undefined,
            msg: "Received invalid string".into(),
        }
    }
}

impl From<std::str::Utf8Error> for Message {
    fn from(_value: std::str::Utf8Error) -> Self {
        Message::Error {
            kind: Error::Undefined,
            msg: "Received invalid string".into(),
        }
    }
}

impl Message {
    /// Try to parse a message out of binary data (e.g. data read from socket)
    ///
    /// # Errors
    /// Many different errors can occur when trying to parse the packet. Any type of incorrect formatting will cause
    /// an error.
    /// 
    /// # Return
    /// This function returns a message whether or not it succeeds. In the [`core::result::Result::Ok`] case,
    /// a message was properly parsed from the data. In the [`core::result::Result::Err`] case, parsing failed
    /// and the method is returning a message that can be sent back to the client as an error message.
    pub(crate) fn try_from_bytes(data: &[u8]) -> Result<Self, Self> {
        if data.len() < 4 {
            return Err(Self::Error {
                kind: Error::Undefined,
                msg: "request not a valid size".into(),
            });
        }
        let op = u16::from_be_bytes(data[..2].try_into().unwrap());
        let op = Operation::try_from(op)?;
        match op {
            Operation::Ack => Message::parse_ack(&data[2..]),
            Operation::Data => Message::parse_data(&data[2..]),
            Operation::Error => Message::parse_error(&data[2..]),
            Operation::Rrq => Message::parse_req(true, &data[2..]),
            Operation::Wrq => Message::parse_req(false, &data[2..]),
        }
    }

    /// Converts the message to a vector that can be then sent over the socket as a TFTP message
    pub(crate) fn to_vec(&self) -> Vec<u8> {
        match self {
            Message::Ack { block } => {
                let mut data = Vec::with_capacity(4);
                data.extend((Operation::Ack as u16).to_be_bytes());
                data.extend(block.to_be_bytes());
                data
            }
            Message::Data { block, data } => {
                let mut bytes = Vec::with_capacity(data.len() + 4);
                bytes.extend((Operation::Data as u16).to_be_bytes());
                bytes.extend(block.to_be_bytes());
                bytes.extend(data);
                bytes
            }
            Message::Error { kind, msg } => {
                let mut bytes = Vec::with_capacity(4 + msg.len());
                bytes.extend((Operation::Error as u16).to_be_bytes());
                bytes.extend((*kind as u16).to_be_bytes());
                bytes.extend(msg.as_bytes());
                bytes.push(0);
                bytes
            }
            Message::Request {
                read,
                filename,
                mode,
            } => {
                // Make sure the bytes have enough capacity for any message size
                let mut bytes = Vec::with_capacity(512);
                if *read {
                    bytes.extend((Operation::Rrq as u16).to_be_bytes());
                } else {
                    bytes.extend((Operation::Wrq as u16).to_be_bytes());
                }
                bytes.extend(
                    filename
                        .to_str()
                        .expect("Path is invalid UTF8 string")
                        .as_bytes(),
                );
                bytes.push(0);
                bytes.extend(mode.to_str());
                bytes
            }
        }
    }

    /// Parses the Ack message type
    ///
    /// See [`Message::try_from_bytes`] for interpreting the return value.
    fn parse_ack(data: &[u8]) -> Result<Self, Self> {
        // We know from [`try_from_bytes`] that data must be at least two
        // so we can just pull a u16 from data and return it
        let block = u16::from_be_bytes(data.try_into().unwrap());
        Ok(Self::Ack { block })
    }

    /// Parses the Data message type
    ///
    /// See [`Message::try_from_bytes`] for interpreting the return value.
    fn parse_data(data: &[u8]) -> Result<Self, Self> {
        if data.len() < 3 {
            return Err(Self::Error {
                kind: Error::Undefined,
                msg: "Data packet must be at least 5 bytes".into(),
            });
        }
        let block = u16::from_be_bytes(data[..2].try_into().unwrap());
        let file_data = data[2..].to_vec();
        Ok(Message::Data {
            block,
            data: file_data,
        })
    }
    /// Parses the Error message type
    ///
    /// See [`Message::try_from_bytes`] for interpreting the return value.
    fn parse_error(data: &[u8]) -> Result<Self, Self> {
        if data.len() < 4 {
            return Err(Self::Error {
                kind: Error::Undefined,
                msg: "Error message should have at least 4 bytes".into(),
            });
        }
        let kind = u16::from_be_bytes(data[..2].try_into().unwrap());
        let kind = Error::try_from(kind)?;
        let msg = CStr::from_bytes_until_nul(&data[2..])?.to_str()?;
        Ok(Self::Error {
            kind,
            msg: msg.into(),
        })
    }
    /// Parses the Read and Write Request message type
    ///
    /// See [`Message::try_from_bytes`] for interpreting the return value.
    fn parse_req(read: bool, data: &[u8]) -> Result<Self, Self> {
        let path = CStr::from_bytes_until_nul(data)?;
        let path_size = path.to_bytes().len();
        let path = PathBuf::from(path.to_str()?);
        let mode = &data[path_size + 1..];
        let mode_str = CStr::from_bytes_until_nul(mode)?;
        let mode = Mode::try_from(mode_str.to_str()?)?;
        Ok(Message::Request {
            read,
            filename: path,
            mode,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_operator_parsing() {
        assert_eq!(Operation::Rrq, Operation::try_from(1).unwrap());
        assert_eq!(Operation::Wrq, Operation::try_from(2).unwrap());
        assert_eq!(Operation::Data, Operation::try_from(3).unwrap());
        assert_eq!(Operation::Ack, Operation::try_from(4).unwrap());
        assert_eq!(Operation::Error, Operation::try_from(5).unwrap());
        assert!(Operation::try_from(88).is_err());
        assert!(Operation::try_from(0).is_err());
    }

    #[test]
    fn test_mode_parsing() {
        assert_eq!(Mode::NetAscii, Mode::try_from("nEtAscII").unwrap());
        assert_eq!(Mode::NetAscii, Mode::try_from("NETASCII").unwrap());
        assert_eq!(Mode::NetAscii, Mode::try_from("netascii").unwrap());

        assert_eq!(Mode::Mail, Mode::try_from("MaIl").unwrap());
        assert_eq!(Mode::Mail, Mode::try_from("MAIL").unwrap());
        assert_eq!(Mode::Mail, Mode::try_from("mail").unwrap());

        assert_eq!(Mode::Octet, Mode::try_from("ocTEt").unwrap());
        assert_eq!(Mode::Octet, Mode::try_from("OCTET").unwrap());
        assert_eq!(Mode::Octet, Mode::try_from("octet").unwrap());
    }

    #[test]
    fn test_data_message_parsing() {
        let data_message = &[0, 3, 0, 9, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let data = Message::try_from_bytes(data_message);
        assert!(data.is_ok());
        let data = data.unwrap();
        match data {
            Message::Data { block, data } => {
                assert_eq!(block, 9);
                assert_eq!(data.len(), 9);
                assert_eq!(data, [1, 2, 3, 4, 5, 6, 7, 8, 9]);
            }
            _ => assert!(false),
        }
    }

    #[test]
    fn test_error_parsing() {
        let error_message = &[0, 5, 0, 2, b'h', b'e', b'l', b'l', b'o', 0];
        let error = Message::try_from_bytes(error_message);
        assert!(error.is_ok());
        let error = error.unwrap();
        match error {
            Message::Error { kind, msg } => {
                assert_eq!(Error::AccessViolation, kind);
                assert_eq!("hello", msg);
            }
            _ => assert!(false),
        }
    }

    #[test]
    fn test_ack_parsing() {
        let ack_message = &[0, 4, 0x1, 0x2];
        let ack = Message::try_from_bytes(ack_message);
        assert!(ack.is_ok());
        let ack = ack.unwrap();
        match ack {
            Message::Ack { block } => assert_eq!(0x102, block),
            _ => assert!(false),
        }
    }

    #[test]
    fn test_req_parsing() {
        let read_req = &[
            0, 1, b'/', b'a', b'b', b'c', b'/', b'd', b'e', b'f', 0, b'o', b'c', b't', b'e', b't',
            0,
        ];
        let read = Message::try_from_bytes(read_req);
        assert!(read.is_ok());
        let read = read.unwrap();
        match read {
            Message::Request {
                read,
                filename,
                mode,
            } => {
                assert!(read);
                assert_eq!(filename, PathBuf::from("/abc/def"));
                assert_eq!(Mode::Octet, mode);
            }
            _ => assert!(false),
        }

        let write_req = &[
            0, 2, b'.', b'/', b'q', b'e', b'd', b'/', b'b', b'f', b'g', 0, b'm', b'a', b'i', b'l',
            0,
        ];
        let write = Message::try_from_bytes(write_req);
        assert!(write.is_ok());
        let write = write.unwrap();
        match write {
            Message::Request {
                read,
                filename,
                mode,
            } => {
                assert!(!read);
                assert_eq!(filename, PathBuf::from("./qed/bfg"));
                assert_eq!(Mode::Mail, mode);
            }
            _ => assert!(false),
        }
    }
}
