use std::convert::TryInto;

use crate::structs::{self, CentrifugeError, rtp::RtpHeader, rtp::RtcpHeader};
pub fn extract(remaining: &[u8]) -> Result<structs::rtp::RTP, CentrifugeError> {
    if remaining.len() < 12 {
        return Err(structs::CentrifugeError::WrongProtocol);
    }
    let rtp_version = remaining[0] >> 6;
    if rtp_version != 2 {
        return Err(structs::CentrifugeError::WrongProtocol);
    }
    let rtp_payload = remaining[1] & 0x7f;
    if rtp_payload < 64 || rtp_payload >= 96 {
        let header = RtpHeader {
            cc: remaining[0] & 0x0f,
            extension: (remaining[0] >> 4) & 1,
            padding: (remaining[0] >> 5) & 1,
            version: rtp_version,
            payload: rtp_payload,
            marker: (remaining[1] >> 7) & 1,
            seqnum: u16::from_be_bytes(remaining[2..4].try_into().unwrap()),
            timestamp: u32::from_be_bytes(remaining[4..8].try_into().unwrap()),
            ssrc: u32::from_be_bytes(remaining[8..12].try_into().unwrap()),
        };
        if remaining.len() < 12 + header.cc as usize * 4 {
            return Err(structs::CentrifugeError::WrongProtocol);    
        }
        let payload_offset;
        if header.extension != 0 {
            if remaining.len() < 12 + header.cc as usize * 4 + 4 {
                return Err(structs::CentrifugeError::WrongProtocol);    
            }
            let ext_len = &remaining[(12 + header.cc as usize * 4 + 2)..];
            let ext_len = u16::from_be_bytes(ext_len[..2].try_into().unwrap());
            payload_offset = 12 + header.cc as usize * 4 + 4 + ext_len as usize * 4;
        } else {
            payload_offset = 12 + header.cc as usize * 4;
        }
        if remaining.len() < 12 + payload_offset {
            return Err(structs::CentrifugeError::WrongProtocol);    
        }
        return Ok(structs::rtp::RTP::Rtp(header, remaining[payload_offset..].to_owned()));
    } else if rtp_payload >= 64 && rtp_payload < 96 {
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
        return Ok(structs::rtp::RTP::Rtcp(header, remaining[8..].to_owned()));
    } else {
        return Err(structs::CentrifugeError::WrongProtocol);
    }
}
