use std::str::from_utf8;

use pktparse::udp::{self, UdpHeader};
use crate::centrifuge::rtp;
use crate::centrifuge::rtcp;
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
    } else if is_rtp(udp_hdr, remaining) {
        let rtp = rtp::extract(remaining)?;
        Ok(UDP::Rtp(rtp))
    } else if is_rtcp(udp_hdr, remaining) {
        let rtcp = rtcp::extract(remaining)?;
        Ok(UDP::Rtcp(rtcp))
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

fn is_rtp(udp_hdr: &UdpHeader, remaining: &[u8]) -> bool {
    if udp_hdr.length < 12 {
        return false;
    }
    if udp_hdr.source_port % 2 == 0 && udp_hdr.dest_port % 2 == 0 {
        let rtp_version = remaining[0] >> 6;
        if rtp_version != 2 {
            return false;
        }
        let rtp_payload = remaining[1] & 0x7f;
        if rtp_payload < 64 || rtp_payload >= 96 {
            return true;
        }
    }
    false
}


fn is_rtcp(udp_hdr: &UdpHeader, remaining: &[u8]) -> bool {
    if udp_hdr.length < 12 {
        return false;
    }
    if udp_hdr.source_port % 2 == 1 && udp_hdr.dest_port % 2 == 1 {
        let rtcp_version = remaining[0] >> 6;
        if rtcp_version != 2 {
            return false;
        }
        let rtp_payload = remaining[1] & 0x7f;
        if rtp_payload >= 64 && rtp_payload < 96 {
            return true;
        }
    }
    false
}
