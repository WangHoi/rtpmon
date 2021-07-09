use serde::Serialize;
use super::NoiseLevel;

#[derive(Debug, PartialEq, Serialize, Clone)]
pub struct RtcpHeader {
    pub rc: u8, // reception report count
    pub padding: u8, // padding 
    pub version: u8, // version = 2
    pub payload: u8, // packet type
    pub length: u16, // length minus one, include header and padding, typical value: htons(1)
    pub ssrc: u32,
}
#[derive(Debug, PartialEq, Serialize, Clone)]
pub struct RTCP {
    pub header: RtcpHeader,
    pub payload: Vec<u8>,
}

impl RTCP {
    pub fn noise_level(&self) -> NoiseLevel {
        NoiseLevel::Zero
    }
}
