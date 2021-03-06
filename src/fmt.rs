use std::sync::Arc;

use ansi_term::Color::{self, Blue, Fixed, Green, Purple, Red, Yellow};
use reduce::Reduce;
use std::cmp;
use std::fmt::Debug;

use crate::structs::arp;
use crate::structs::ether;
use crate::structs::ip::IPHeader;
use crate::structs::ipv4;
use crate::structs::ipv6;
use crate::structs::prelude::*;
use crate::structs::raw::Raw;
use crate::structs::rtcp;
use crate::structs::rtp;
use crate::structs::tcp;
use crate::structs::udp;
use crate::structs::NoiseLevel;

const GREY: u8 = 245;

pub struct Config {
    fmt: Format,
    filter: Arc<Filter>,
}

impl Config {
    pub fn new(layout: Layout, verbosity: u8, colors: bool) -> Config {
        Config {
            fmt: Format::new(layout, colors),
            filter: Arc::new(Filter::new(verbosity)),
        }
    }

    pub fn filter(&self) -> Arc<Filter> {
        self.filter.clone()
    }

    pub fn format(self) -> Format {
        self.fmt
    }
}

pub enum Layout {
    Compact,
    Debugging,
    Json,
}

pub struct Format {
    layout: Layout,
    colors: bool,
}

impl Format {
    pub fn new(layout: Layout, colors: bool) -> Format {
        Format { layout, colors }
    }

    #[inline]
    pub fn print(&self, packet: Raw) {
        match self.layout {
            Layout::Compact => self.print_compact(packet),
            Layout::Debugging => self.print_debugging(packet),
            Layout::Json => self.print_json(&packet),
        }
    }

    #[inline]
    fn colorify(&self, color: Color, out: String) -> String {
        if self.colors {
            color.normal().paint(out).to_string()
        } else {
            out
        }
    }

    #[inline]
    fn print_compact(&self, packet: Raw) {
        let mut out = String::new();

        use crate::structs::raw::Raw::Unknown;
        let color = match packet {
            Ether(eth_frame, eth) => {
                out += &format!(
                    "{} -> {}, ",
                    display_macaddr(&eth_frame.source_mac),
                    display_macaddr(&eth_frame.dest_mac)
                );

                self.format_compact_eth(&mut out, eth)
            }
            Tun(eth) => self.format_compact_eth(&mut out, eth),
            Unknown(data) => self.format_compact_unknown_data(&mut out, &data),
        };

        println!(
            "{}",
            match color {
                Some(color) => self.colorify(color, out),
                None => out,
            }
        );
    }

    #[inline]
    fn format_compact_unknown_data(&self, out: &mut String, data: &[u8]) -> Option<Color> {
        out.push_str(&format!("[unknown] {:?}", data));
        None
    }

    #[inline]
    fn format_compact_eth(&self, out: &mut String, eth: ether::Ether) -> Option<Color> {
        match eth {
            Arp(arp_pkt) => self.format_compact_arp(out, arp_pkt),
            IPv4(ip_hdr, ipv4) => self.format_compact_ipv4(out, &ip_hdr, ipv4),
            IPv6(ip_hdr, ipv6) => self.format_compact_ipv6(out, &ip_hdr, ipv6),
            ether::Ether::Unknown(data) => self.format_compact_unknown_data(out, &data),
        }
    }

    #[inline]
    fn format_compact_arp(&self, out: &mut String, arp_pkt: arp::ARP) -> Option<Color> {
        use crate::structs::arp::ARP;
        out.push_str(&match arp_pkt {
            ARP::Request(arp_pkt) => {
                format!(
                    "[arp/request] {:15}   ?                         (tell {}, {})",
                    format!("{}", arp_pkt.dest_addr),
                    format!("{}", arp_pkt.src_addr),
                    display_macaddr(&arp_pkt.src_mac)
                )
            }
            ARP::Reply(arp_pkt) => {
                format!(
                    "[arp/reply  ] {:15}   ! => {}    (fyi  {}, {})",
                    format!("{}", arp_pkt.src_addr),
                    display_macaddr(&arp_pkt.src_mac),
                    format!("{}", arp_pkt.dest_addr),
                    display_macaddr(&arp_pkt.dest_mac)
                )
            }
        });
        Some(Blue)
    }

    #[inline]
    fn format_compact_ipv4<IP: IPHeader>(
        &self,
        out: &mut String,
        ip_hdr: &IP,
        next: ipv4::IPv4,
    ) -> Option<Color> {
        match next {
            ipv4::IPv4::TCP(tcp_hdr, tcp) => self.format_compact_ip_tcp(out, ip_hdr, &tcp_hdr, tcp),
            ipv4::IPv4::UDP(udp_hdr, udp) => self.format_compact_ip_udp(out, ip_hdr, &udp_hdr, udp),
            ipv4::IPv4::Unknown(data) => self.format_compact_ip_unknown(out, ip_hdr, &data),
        }
    }

    #[inline]
    fn format_compact_ipv6<IP: IPHeader>(
        &self,
        out: &mut String,
        ip_hdr: &IP,
        next: ipv6::IPv6,
    ) -> Option<Color> {
        match next {
            ipv6::IPv6::TCP(tcp_hdr, tcp) => self.format_compact_ip_tcp(out, ip_hdr, &tcp_hdr, tcp),
            ipv6::IPv6::UDP(udp_hdr, udp) => self.format_compact_ip_udp(out, ip_hdr, &udp_hdr, udp),
            ipv6::IPv6::Unknown(data) => self.format_compact_ip_unknown(out, ip_hdr, &data),
        }
    }

    #[inline]
    fn format_compact_ip_unknown<IP: IPHeader>(
        &self,
        out: &mut String,
        ip_hdr: &IP,
        data: &[u8],
    ) -> Option<Color> {
        out.push_str(&format!(
            "[unknown] {} -> {} {:?}",
            ip_hdr.source_addr(),
            ip_hdr.dest_addr(),
            data
        ));
        None
    }

    #[inline]
    fn format_compact_ip_udp<IP: IPHeader>(
        &self,
        out: &mut String,
        ip_hdr: &IP,
        udp_hdr: &pktparse::udp::UdpHeader,
        udp: udp::UDP,
    ) -> Option<Color> {
        out.push_str(&format!(
            "[udp   ] {:22} -> {:22} ",
            format!("{}:{}", ip_hdr.source_addr(), udp_hdr.source_port),
            format!("{}:{}", ip_hdr.dest_addr(), udp_hdr.dest_port)
        ));

        use crate::structs::udp::UDP::*;
        match udp {
            Rtp(rtp::RTP { header, .. }) => {
                out.push_str(&format!(
                    "[rtp   ] pt={} ssrc={} seq={} time={}",
                    header.payload, header.ssrc, header.seqnum, header.timestamp
                ));
                Some(Blue)
            }
            Rtcp(rtcp::RTCP { header, .. }) => {
                out.push_str(&format!(
                    "[rtcp  ] pt={} ssrc={}",
                    header.payload, header.ssrc
                ));
                Some(Blue)
            }
            Text(text) => {
                out.push_str(&format!("[text] {:?}", text));
                Some(Red)
            }
            Binary(x) => {
                out.push_str(&format!("[binary] {:?}", x));
                Some(Red)
            }
        }
    }

    #[inline]
    fn format_compact_ip_tcp<IP: IPHeader>(
        &self,
        out: &mut String,
        ip_hdr: &IP,
        tcp_hdr: &pktparse::tcp::TcpHeader,
        tcp: tcp::TCP,
    ) -> Option<Color> {
        let mut flags = String::new();
        if tcp_hdr.flag_syn {
            flags.push('S')
        }
        if tcp_hdr.flag_ack {
            flags.push('A')
        }
        if tcp_hdr.flag_rst {
            flags.push('R')
        }
        if tcp_hdr.flag_fin {
            flags.push('F')
        }

        out.push_str(&format!(
            "[tcp/{:2}] {:22} -> {:22} ",
            flags,
            format!("{}:{}", ip_hdr.source_addr(), tcp_hdr.source_port),
            format!("{}:{}", ip_hdr.dest_addr(), tcp_hdr.dest_port)
        ));

        use crate::structs::tcp::TCP::*;
        match tcp {
            Text(text) => {
                out.push_str(&format!("[text] {:?}", text));
                Some(Red)
            }
            Binary(x) => {
                out.push_str(&format!("[binary] {:?}", x));
                Some(Red)
            }
            Empty => Some(Fixed(GREY)),
        }
    }

    #[inline]
    fn print_debugging(&self, packet: Raw) {
        use crate::structs::raw::Raw::Unknown;
        match packet {
            Ether(eth_frame, eth) => {
                println!("eth: {:?}", eth_frame);
                self.print_debugging_eth(1, eth);
            }
            Tun(eth) => self.print_debugging_eth(0, eth),
            Unknown(data) => println!("unknown: {:?}", data),
        }
    }

    #[inline]
    fn print_debugging_eth(&self, indent: usize, eth: ether::Ether) {
        match eth {
            Arp(arp_pkt) => {
                println!(
                    "{}{}",
                    "\t".repeat(indent),
                    self.colorify(Blue, format!("arp: {:?}", arp_pkt))
                );
            }
            IPv4(ip_hdr, ipv4::IPv4::TCP(tcp_hdr, tcp)) => {
                println!("{}ipv4: {:?}", "\t".repeat(indent), ip_hdr);
                println!("{}tcp: {:?}", "\t".repeat(indent + 1), tcp_hdr);
                println!(
                    "{}{}",
                    "\t".repeat(indent + 2),
                    self.print_debugging_tcp(tcp)
                );
            }
            IPv4(ip_hdr, ipv4::IPv4::UDP(udp_hdr, udp)) => {
                println!("{}ipv4: {:?}", "\t".repeat(indent), ip_hdr);
                println!("{}udp: {:?}", "\t".repeat(indent + 1), udp_hdr);
                println!(
                    "{}{}",
                    "\t".repeat(indent + 2),
                    self.print_debugging_udp(udp)
                );
            }
            IPv4(ip_hdr, ipv4::IPv4::Unknown(data)) => {
                println!("{}ipv4: {:?}", "\t".repeat(indent), ip_hdr);
                println!("{}unknown: {:?}", "\t".repeat(indent + 1), data);
            }
            IPv6(ip_hdr, ipv6::IPv6::TCP(tcp_hdr, tcp)) => {
                println!("{}ipv6: {:?}", "\t".repeat(indent), ip_hdr);
                println!("{}tcp: {:?}", "\t".repeat(indent + 1), tcp_hdr);
                println!(
                    "{}{}",
                    "\t".repeat(indent + 2),
                    self.print_debugging_tcp(tcp)
                );
            }
            IPv6(ip_hdr, ipv6::IPv6::UDP(udp_hdr, udp)) => {
                println!("{}ipv6: {:?}", "\t".repeat(indent), ip_hdr);
                println!("{}udp: {:?}", "\t".repeat(indent + 1), udp_hdr);
                println!(
                    "{}{}",
                    "\t".repeat(indent + 2),
                    self.print_debugging_udp(udp)
                );
            }
            IPv6(ip_hdr, ipv6::IPv6::Unknown(data)) => {
                println!("{}ipv6: {:?}", "\t".repeat(indent), ip_hdr);
                println!("{}unknown: {:?}", "\t".repeat(indent + 1), data);
            }
            ether::Ether::Unknown(data) => {
                println!("{}unknown: {:?}", "\t".repeat(indent), data);
            }
        }
    }

    #[inline]
    fn print_debugging_tcp(&self, tcp: tcp::TCP) -> String {
        use crate::structs::tcp::TCP::*;
        match tcp {
            Text(text) => self.colorify(Blue, format!("remaining: {:?}", text)),
            Binary(x) => self.colorify(Yellow, format!("remaining: {:?}", x)),
            Empty => self.colorify(Fixed(GREY), String::new()),
        }
    }

    #[inline]
    fn print_debugging_udp(&self, udp: udp::UDP) -> String {
        use crate::structs::udp::UDP::*;
        match udp {
            Rtp(rtp) => self.colorify(Blue, format!("remaining: {:?}", rtp)),
            Rtcp(rtcp) => self.colorify(Blue, format!("remaining: {:?}", rtcp)),
            Text(text) => self.colorify(Blue, format!("remaining: {:?}", text)),
            Binary(x) => self.colorify(Yellow, format!("remaining: {:?}", x)),
        }
    }

    #[inline]
    fn print_json(&self, packet: &Raw) {
        println!("{}", serde_json::to_string(packet).unwrap());
    }
}

pub struct Filter {
    pub verbosity: u8,
}

impl Filter {
    #[inline]
    pub fn new(verbosity: u8) -> Filter {
        let verbosity = cmp::min(verbosity, NoiseLevel::Maximum.into_u8());
        Filter { verbosity }
    }

    #[inline]
    pub fn matches(&self, packet: &Raw) -> bool {
        packet.noise_level().into_u8() <= self.verbosity
    }
}

#[inline]
fn align(len: usize, a: &str) -> String {
    format!("\n{}{}", " ".repeat(len), &a)
}

// TODO: upstream
#[inline]
fn display_macaddr(mac: &pktparse::ethernet::MacAddress) -> String {
    display_macadr_buf(mac.0)
}

#[inline]
fn display_macadr_buf(mac: [u8; 6]) -> String {
    let mut string = mac
        .iter()
        .fold(String::new(), |acc, &x| format!("{}{:02x}:", acc, x));
    string.pop();
    string
}

#[inline]
fn display_kv_list(list: &[(&str, Option<&str>)]) -> String {
    Reduce::reduce(
        list.iter().filter_map(|&(key, ref value)| {
            value.as_ref().map(|value| format!("{}: {:?}", key, value))
        }),
        |a, b| a + ", " + &b,
    )
    .map(|extra| format!(" ({})", extra))
    .unwrap_or_else(String::new)
}

struct DhcpKvListWriter<'a> {
    elements: Vec<(&'a str, String)>,
}

impl<'a> DhcpKvListWriter<'a> {
    fn new() -> DhcpKvListWriter<'a> {
        DhcpKvListWriter { elements: vec![] }
    }

    fn append<T: Debug>(mut self, key: &'a str, value: &Option<T>) -> Self {
        if let Some(value) = value {
            self.elements.push((key, format!("{:?}", value)));
        }
        self
    }

    fn finalize(self) -> String {
        Reduce::reduce(
            self.elements
                .iter()
                .map(|&(key, ref value)| format!("{}: {}", key, value)),
            |a, b| a + ", " + &b,
        )
        .map(|extra| format!(" ({})", extra))
        .unwrap_or_else(String::new)
    }
}
