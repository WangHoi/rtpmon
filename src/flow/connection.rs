use log;
use crate::{flow::FlowDirection, structs::rtp::{RTP, RtpHeader}};
use super::{FlowData, FlowHeader, FlowPacket, FlowPayload, FlowType};
use std::{collections::HashMap, net::SocketAddr, time::{Duration, SystemTime}};

#[derive(Clone)]
pub struct ConnectionHeader {
    pub ftype: FlowType,
    pub local: SocketAddr,
    pub remote: SocketAddr,
}
#[derive(Clone)]
pub struct Connection {
    pub header: ConnectionHeader,
    pub ingress_pkts: Vec<FlowPacket>,
    pub egress_pkts: Vec<FlowPacket>,
}

impl Connection {
    pub fn valid(&self) -> bool {
        !self.ingress_pkts.is_empty() && !self.egress_pkts.is_empty()
    }
    pub fn ingress_tsrange(&self) -> Option<(SystemTime, SystemTime)> {
        if let Some(p1) = self.ingress_pkts.first() {
            if let Some(p2) = self.ingress_pkts.last() {
                return Some((p1.ts, p2.ts));
            }
        }
        None
    }
    pub fn ingress_ssrc(&self) -> Option<u32> {
        if let Some(p1) = self.ingress_pkts.first() {
            if let FlowPayload::Rtp(ref rtp) = p1.payload {
                return Some(rtp.header.ssrc);
            }
        }
        None
    }
    pub fn egress_tsrange(&self) -> Option<(SystemTime, SystemTime)> {
        if let Some(p1) = self.egress_pkts.first() {
            if let Some(p2) = self.egress_pkts.last() {
                return Some((p1.ts, p2.ts));
            }
        }
        None
    }
    pub fn egress_ssrc(&self) -> Option<u32> {
        if let Some(p1) = self.egress_pkts.first() {
            if let FlowPayload::Rtp(ref rtp) = p1.payload {
                return Some(rtp.header.ssrc);
            }
        }
        None
    }
}
#[derive(PartialEq, Eq, Hash, Clone)]
pub struct ConnectionKey {
    pub remote: SocketAddr,
    // pub ssrc: u32,
}
pub struct ConnectionMap {
    pub map: HashMap<ConnectionKey, Vec<Connection>>,
}

impl ConnectionMap {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }
    pub fn add(&mut self, d: FlowData) {
        if let FlowPayload::Rtp(ref rtp) = d.payload {
            let key = ConnectionKey {
                remote: d.header.remote,
                // ssrc: rtp.header.ssrc,
            };
            match self.map.get_mut(&key) {
                Some(conn_list) => {
                    if let Some(conn) = find_conn(d.ts, d.header.dir, &rtp, conn_list) {
                        conn_add_flow_data(conn, d);
                    } else {
                        let mut conn = make_conn(&d.header);
                        conn_add_flow_data(&mut conn, d);
                        conn_list.push(conn);
                    }
                },
                None => {
                    let mut conn = make_conn(&d.header);
                    conn_add_flow_data(&mut conn, d);
                    self.map.insert(key, vec![conn]);
                },
            }
        }
    }
}
const THREHOLD_SECS: u64 = 1;
fn find_conn<'a>(ts: SystemTime, dir: FlowDirection, rtp: &RTP, list: &'a mut Vec<Connection>) -> Option<&'a mut Connection> {
    for c in list.iter_mut().rev() {
        if dir == FlowDirection::Ingress {
            if let Some(ssrc) = c.ingress_ssrc() {
                if ssrc == rtp.header.ssrc {
                    return Some(c);
                }
            } else if let Some((first, last)) = c.egress_tsrange() {
                let first = first.checked_sub(Duration::from_secs(THREHOLD_SECS)).unwrap();
                let last = last.checked_add(Duration::from_secs(THREHOLD_SECS)).unwrap();
                if first <= ts && ts <= last {
                    return Some(c);
                }
            }
        } else {
            if let Some(ssrc) = c.egress_ssrc() {
                if ssrc == rtp.header.ssrc {
                    return Some(c);
                }
            } else if let Some((first, last)) = c.ingress_tsrange() {
                let first = first.checked_sub(Duration::from_secs(THREHOLD_SECS)).unwrap();
                let last = last.checked_add(Duration::from_secs(THREHOLD_SECS)).unwrap();
                if first <= ts && ts <= last {
                    return Some(c);
                }
            }
        }
    }
    None
}
fn make_conn(header: &FlowHeader) -> Connection {
    let header = ConnectionHeader {
        ftype: header.ftype,
        local: header.local,
        remote: header.remote,
    };
    Connection {
        header,
        ingress_pkts: vec![],
        egress_pkts: vec![],
    }
}
fn conn_add_flow_data(conn: &mut Connection, d: FlowData) {
    if d.header.dir == FlowDirection::Ingress {
        conn.ingress_pkts.push(FlowPacket {
            ts: d.ts,
            payload: d.payload,
        });
    } else {
        conn.egress_pkts.push(FlowPacket {
            ts: d.ts,
            payload: d.payload,
        });
    }
}