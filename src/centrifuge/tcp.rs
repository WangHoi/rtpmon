use std::str::from_utf8;

use pktparse::tcp::{self, TcpHeader};

use crate::structs::CentrifugeError;
use crate::structs::tcp::TCP;


pub fn parse(remaining: &[u8]) -> Result<(tcp::TcpHeader, TCP), CentrifugeError> {
    if let Ok((remaining, tcp_hdr)) = tcp::parse_tcp_header(remaining) {
        let inner = match extract(&tcp_hdr, remaining) {
            Ok(x) => x,
            Err(_) => unknown(remaining),
        };
        Ok((tcp_hdr, inner))
    } else {
        Err(CentrifugeError::InvalidPacket)
    }
}

#[inline]
pub fn extract(_tcp_hdr: &TcpHeader, remaining: &[u8]) -> Result<TCP, CentrifugeError> {
    if remaining.is_empty() {
        Ok(TCP::Empty)
    } else {
        Err(CentrifugeError::UnknownProtocol)
    }
}

#[inline]
pub fn unknown(remaining: &[u8]) -> TCP {
    // if slice contains null bytes, don't try to decode
    if remaining.contains(&0) {
        TCP::Binary(remaining.to_vec())
    } else {
        match from_utf8(remaining) {
            Ok(remaining) => TCP::Text(remaining.to_owned()),
            Err(_) => TCP::Binary(remaining.to_vec()),
        }
    }
}
