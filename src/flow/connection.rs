use crate::flow::FlowDirection;

use super::{FlowHeader, FlowData, FlowPacket};
use std::{collections::HashMap, net::SocketAddr};

pub struct ConnectionHeader {
    local: SocketAddr,
    remote: SocketAddr,
}
pub struct Connection {
    header: ConnectionHeader,
    ingress_pkts: Vec<FlowPacket>,
    egress_pkts: Vec<FlowPacket>,
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
