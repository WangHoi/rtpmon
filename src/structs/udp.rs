use crate::structs::NoiseLevel;
use serde::Serialize;

#[derive(Debug, PartialEq, Serialize)]
pub enum UDP {
    Text(String),
    Binary(Vec<u8>),
}

impl UDP {
    pub fn noise_level(&self) -> NoiseLevel {
        use self::UDP::*;
        match *self {
            Text(_) => NoiseLevel::Two,
            Binary(_) => NoiseLevel::AlmostMaximum,
        }
    }
}
