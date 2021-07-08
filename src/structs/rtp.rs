use serde::Serialize;
use super::NoiseLevel;

#[derive(Debug, PartialEq, Serialize, Clone)]
pub struct RtpHeader {
    pub cc: u8,
    pub extension: u8,
    pub padding: u8,
    pub version: u8,
    pub payload: u8,
    pub marker: u8,
    pub seqnum: u16,
    pub timestamp: u32,
    pub ssrc: u32,
}
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
pub enum RTP {
    Rtp(RtpHeader, Vec<u8>),
    Rtcp(RtcpHeader, Vec<u8>),
}

impl RTP {
    pub fn noise_level(&self) -> NoiseLevel {
        NoiseLevel::Zero
    }
}
