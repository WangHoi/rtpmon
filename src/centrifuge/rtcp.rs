use std::convert::TryInto;

use crate::structs::{self, CentrifugeError, rtcp::RtcpHeader};
pub fn extract(remaining: &[u8]) -> Result<structs::rtcp::RTCP, CentrifugeError> {
    if remaining.len() < 12 {
        return Err(structs::CentrifugeError::WrongProtocol);
    }
    let rtp_version = remaining[0] >> 6;
    if rtp_version != 2 {
        return Err(structs::CentrifugeError::WrongProtocol);
    }
    let rtp_payload = remaining[1] & 0x7f;
    if rtp_payload >= 64 && rtp_payload < 96 {
        let payload = remaining[1];
        let header = RtcpHeader {
            rc: remaining[0] & 0x1f,
            padding: (remaining[0] >> 5) & 1,
            version: rtp_version,
            payload,
            length: u16::from_be_bytes(remaining[2..4].try_into().unwrap()),
            ssrc: u32::from_be_bytes(remaining[4..8].try_into().unwrap()),
        };
        if remaining.len() < 8 {
            return Err(structs::CentrifugeError::WrongProtocol);    
        }
        return Ok(structs::rtcp::RTCP {
            header,
            payload: remaining[8..].to_owned(),
        });
    } else {
        return Err(structs::CentrifugeError::WrongProtocol);
    }
}
