use thiserror::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[repr(u16)]
pub enum Error {
    #[error("Undefined error occurred")]
    Undefined = 0,
    #[error("File not found")]
    NotFound = 1,
    #[error("Access violation")]
    AccessViolation = 2,
    #[error("Disk full or allocation exceeded")]
    DiskFull = 3,
    #[error("Illegal TFTP operation")]
    Illegal = 4,
    #[error("Unknown transfer ID")]
    UnknownID = 5,
    #[error("File already exists")]
    AlreadyExist = 6,
    #[error("No such user")]
    NoUser = 7,
}

impl std::convert::TryFrom<u16> for Error {
    type Error = Error;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Error::Undefined),
            1 => Ok(Error::NotFound),
            2 => Ok(Error::AccessViolation),
            3 => Ok(Error::DiskFull),
            4 => Ok(Error::Illegal),
            5 => Ok(Error::UnknownID),
            6 => Ok(Error::AlreadyExist),
            7 => Ok(Error::NoUser),
            _ => Err(Error::Undefined),
        }
    }
}
