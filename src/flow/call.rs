use crate::flow::{FlowPayload, FlowType};
use std::{collections::HashSet, net::SocketAddr};

use super::{FlowPacket, connection::{Connection, ConnectionHeader, ConnectionMap}};

pub struct CallHeader {
    pub peer1_ssrc: u32,
    pub peer2_ssrc: u32,
    // pub conn_headers: Vec<ConnectionHeader>,
}
pub struct Call {
    pub header: CallHeader,
    pub peer1: Connection,
    pub peer2: Connection,
}

impl Call {
    pub fn compute_stats(&self) -> CallStats {
        let peer1_delay = compute_delay_stats(&self.peer1.ingress_pkts, &self.peer2.egress_pkts);
        let peer2_delay = compute_delay_stats(&self.peer2.ingress_pkts, &self.peer1.egress_pkts);
        CallStats {
            peer1_delay,
            peer2_delay,
        }
    }
}
pub struct DelayStats {
    pub max: u64,
    pub avg: u64,
    pub std: f64,
}
pub struct CallStats {
    pub peer1_delay: DelayStats,
    pub peer2_delay: DelayStats,
}

pub fn extract_calls(conn_list: &Vec<Connection>) -> Vec<Call> {
    let mut mark_set = HashSet::with_capacity(conn_list.len());
    let mut pairs = Vec::with_capacity(conn_list.len());
    let mut calls = Vec::new();
    for (i, conn1) in conn_list.iter().enumerate() {
        if mark_set.contains(&i) {
            continue;
        }
        mark_set.insert(i);
        if i + 1 == conn_list.len() {
            break;
        }
        for (j, conn2) in conn_list[(i + 1)..].iter().enumerate() {
            assert!(conn1.valid()
                && conn2.valid()
                && conn1.header.ftype == conn2.header.ftype
                && conn1.header.ftype == FlowType::Rtp);
            let p1 = conn1.ingress_pkts.first().unwrap().rtp().unwrap();
            let p2 = conn2.egress_pkts.first().unwrap().rtp().unwrap(); 
            let q1 = conn2.ingress_pkts.first().unwrap().rtp().unwrap();
            let q2 = conn1.egress_pkts.first().unwrap().rtp().unwrap(); 
            if p1.header.ssrc == p2.header.ssrc && q1.header.ssrc == q2.header.ssrc {
                mark_set.insert(i + 1 + j);
                pairs.push((conn1, conn2));
            }
        }
    }
    for (peer1, peer2) in pairs.into_iter() {
        let ssrc1 = if let FlowPayload::Rtp(ref p) = peer1.ingress_pkts.first().unwrap().payload {
            p.header.ssrc
        } else {
            unreachable!()
        };
        let ssrc2 = if let FlowPayload::Rtp(ref p) = peer2.ingress_pkts.first().unwrap().payload {
            p.header.ssrc
        } else {
            unreachable!()
        };
        let header = CallHeader {
            peer1_ssrc: ssrc1,
            peer2_ssrc: ssrc2,
        };
        let c = Call {
            header,
            peer1: peer1.clone(),
            peer2: peer2.clone(),
        };
        calls.push(c);
    }
    calls
}
fn compute_delay_stats(ingress_pkts: &[FlowPacket], egress_pkts: &[FlowPacket]) -> DelayStats {
    let mut n = 0u64;
    let mut ec = 0usize;
    let mut dtotal = 0u64;
    let mut dtotal_square = 0u128;
    let mut dmax = 0u64;
    for pkt1 in ingress_pkts {
        let mut ec_adv = 0usize;
        let mut i = 0usize;
        for pkt2 in &egress_pkts[ec..] {
            if pkt2.ts < pkt1.ts {
                ec_adv += 1;
                continue;
            }
            if let FlowPayload::Rtp(ref p1) = pkt1.payload {
                if let FlowPayload::Rtp(ref p2) = pkt2.payload {
                    if p1.header.seqnum == p2.header.seqnum {
                        let d = pkt2.ts.duration_since(pkt1.ts).unwrap().as_micros() as u64;
                        n += 1;
                        if dmax < d {
                            dmax = d;
                        }
                        dtotal += d;
                        dtotal_square += d as u128 * d as u128;
                        break;
                    }
                }
            }
            i += 1;
            if i >= 100 {
                break;
            }
        }
        ec += ec_adv;
    }
    let davg = dtotal / n;
    let dstd = (dtotal_square - dtotal as u128 * dtotal as u128 / n as u128) as f64 / n as f64;
    DelayStats {
        max: dmax,
        avg: davg,
        std: dstd,
    }
}
