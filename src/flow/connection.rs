use log;
use crate::flow::FlowDirection;
use super::{FlowData, FlowHeader, FlowPacket, FlowType};
use std::{collections::HashMap, net::SocketAddr, time::SystemTime};

pub struct ConnectionHeader {
    pub ftype: FlowType,
    pub local: SocketAddr,
    pub remote: SocketAddr,
}
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
    pub fn egress_tsrange(&self) -> Option<(SystemTime, SystemTime)> {
        if let Some(p1) = self.egress_pkts.first() {
            if let Some(p2) = self.egress_pkts.last() {
                return Some((p1.ts, p2.ts));
            }
        }
        None
    }
}
pub struct ConnectionMap {
    // key: remote
    pub map: HashMap<SocketAddr, Connection>,
}

impl ConnectionMap {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }
    pub fn add(&mut self, d: FlowData) {
        match self.map.get_mut(&d.header.remote) {
            Some(conn) => {
                if conn.header.ftype != d.header.ftype {
                    log::error!("FlowType {:?} and {:?} mismatch.", conn.header.ftype, d.header.ftype);
                    return;
                }
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
            },
            None => {
                let header = ConnectionHeader {
                    ftype: d.header.ftype,
                    local: d.header.local,
                    remote: d.header.remote,
                };
                let mut conn = Connection {
                    header,
                    ingress_pkts: vec![],
                    egress_pkts: vec![],
                };
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
                self.map.insert(d.header.remote, conn);
            },
        }
    }
}
