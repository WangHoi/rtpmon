use crate::structs::rtp;
use crate::structs::NoiseLevel;
use serde::Serialize;

#[derive(Debug, PartialEq, Serialize)]
pub enum UDP {
    Rtp(rtp::RTP),
    Text(String),
    Binary(Vec<u8>),
}

impl UDP {
    pub fn noise_level(&self) -> NoiseLevel {
        use self::UDP::*;
        match *self {
            Rtp(ref rtp) => rtp.noise_level(),
            Text(_) => NoiseLevel::Two,
            Binary(_) => NoiseLevel::AlmostMaximum,
        }
    }
}
