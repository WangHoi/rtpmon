use std::str::from_utf8;

use pktparse::udp::{self, UdpHeader};
use crate::centrifuge::rtp;
use crate::structs::CentrifugeError;
use crate::structs::udp::UDP;


pub fn parse(remaining: &[u8]) -> Result<(udp::UdpHeader, UDP), CentrifugeError> {
    if let Ok((remaining, udp_hdr)) = udp::parse_udp_header(remaining) {
        let inner = match extract(&udp_hdr, remaining) {
            Ok(x) => x,
            Err(_) => unknown(remaining),
        };
        Ok((udp_hdr, inner))
    } else {
        Err(CentrifugeError::InvalidPacket)
    }
}

#[inline]
pub fn extract(udp_hdr: &UdpHeader, remaining: &[u8]) -> Result<UDP, CentrifugeError> {
    if remaining.is_empty() {
        Ok(UDP::Binary(Vec::new()))
    } else if (7076..=7079).contains(&udp_hdr.dest_port) || (7076..=7079).contains(&udp_hdr.source_port) {
        let rtp = rtp::extract(remaining)?;
        Ok(UDP::Rtp(rtp))
    } else {
        Err(CentrifugeError::UnknownProtocol)
    }
}

#[inline]
pub fn unknown(remaining: &[u8]) -> UDP {
    // if slice contains null bytes, don't try to decode
    if remaining.contains(&0) {
        UDP::Binary(remaining.to_vec())
    } else {
        match from_utf8(remaining) {
            Ok(remaining) => {
                UDP::Text(remaining.to_owned())
            }
            Err(_) => UDP::Binary(remaining.to_vec()),
        }
    }
}
