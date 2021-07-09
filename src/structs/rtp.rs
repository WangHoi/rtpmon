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
pub struct RTP {
    pub header: RtpHeader,
    pub payload: Vec<u8>,
}

impl RTP {
    pub fn noise_level(&self) -> NoiseLevel {
        NoiseLevel::Zero
    }
}
