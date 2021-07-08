pub mod connection;

use crate::structs::{ether::Ether, ip::IPHeader, ipv4::IPv4, raw::Raw, udp::UDP, rtp::RTP};
use nom::bitvec::view::AsBits;
use std::{
    collections::VecDeque,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    time::SystemTime,
};

#[derive(PartialEq, Eq, Debug)]
pub enum FlowType {
    Rtp,
    Rtcp,
    Udp,
}
#[derive(PartialEq, Eq, Debug)]
pub enum FlowDirection {
    Ingress,
    Egress,
}
pub struct FlowPacket {
    ts: SystemTime,
    payload: FlowPayload,
}
pub struct FlowHeader {
    ftype: FlowType,
    dir: FlowDirection,
    local: SocketAddr,
    remote: SocketAddr,
}
pub enum FlowPayload {
    Binary(Vec<u8>),
    Text(String),
    Rtp(RTP),
}
pub struct FlowData {
    ts: SystemTime,
    header: FlowHeader,
    payload: FlowPayload,
}

pub fn get_flow_data(local_ip: &Ipv4Addr, ts: SystemTime, raw: &Raw) -> Option<FlowData> {
    if let Raw::Ether(_, ref ether) = raw {
        if let Ether::IPv4(ref v4_hdr, ref v4) = ether {
            if let IPv4::UDP(ref udp_hdr, ref udp) = v4 {
                let src_ip = v4_hdr.source_addr();
                let dst_ip = v4_hdr.dest_addr();
                let src_port = udp_hdr.source_port;
                let dst_port = udp_hdr.dest_port;
                let (dir, local, remote) = if src_ip == *local_ip {
                    (
                        FlowDirection::Egress,
                        SocketAddrV4::new(src_ip, src_port).into(),
                        SocketAddrV4::new(dst_ip, dst_port).into(),
                    )
                } else if dst_ip == *local_ip {
                    (
                        FlowDirection::Ingress,
                        SocketAddrV4::new(dst_ip, dst_port).into(),
                        SocketAddrV4::new(src_ip, src_port).into(),
                    )
                } else {
                    return None;
                };
                let (ftype, payload) = match udp {
                    UDP::Rtp(ref rtp) => (FlowType::Rtp, FlowPayload::Rtp(rtp.clone())),
                    UDP::Binary(ref p) => (FlowType::Udp, FlowPayload::Binary(p.clone())),
                    UDP::Text(ref t) => (FlowType::Udp, FlowPayload::Text(t.clone())),
                };
                let flow = FlowHeader {
                    ftype,
                    dir,
                    local,
                    remote,
                };
                return Some(FlowData {
                    ts,
                    header: flow,
                    payload,
                });
            }
        }
    }
    None
}
