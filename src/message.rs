use std::ffi::{CString, NulError};

use crate::error::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
enum Operation {
    Rrq = 1,
    Wrq = 2,
    Data = 3,
    Ack = 4,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Octet,
    NetAscii,
    Mail,
}

enum Message {
    Request {
        read: bool,
        filename: String,
        mode: Mode,
    },
    Data {
        block: u16,
        data: Vec<u8>,
    },
    Ack {
        block: u16,
    },
    Error {
        kind: Error,
        msg: String,
    },
}

impl From<Box<(dyn std::error::Error + 'static)>> for Message {
    fn from(value: Box<(dyn std::error::Error + 'static)>) -> Self {
        Message::Error {
            kind: Error::Undefined,
            msg: format!("{:?}", value),
        }
    }
}

impl From<NulError> for Message {
    fn from(value: NulError) -> Self {
        Message::Error {
            kind: Error::Undefined,
            msg: "Invalid string received".into(),
        }
    }
}

impl Message {
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
            _ => todo!(),
        }
    }

    fn parse_ack(data: &[u8]) -> Result<Self, Self> {
        // We know from [`try_from_bytes`] that data must be at least two
        // so we can just pull a u16 from data and return it
        let block = u16::from_be_bytes(data.try_into().unwrap());
        Ok(Self::Ack { block })
    }

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

    fn parse_error(data: &[u8]) -> Result<Self, Self> {
        if data.len() < 4 {
            return Err(Self::Error {
                kind: Error::Undefined,
                msg: "Error message should have at least 4 bytes".into(),
            });
        }
        let kind = u16::from_be_bytes(data[..2].try_into().unwrap());
        let kind = Error::try_from(kind)?;
        let msg = CString::new(&data[2..])?;
        Ok(Self::Error { kind, msg: msg.to_string_lossy().into() })
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
    }
}