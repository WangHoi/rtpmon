mod centrifuge;
mod cli;
mod errors;
mod flow;
mod fmt;
mod link;
mod sniff;
mod structs;

use crate::cli::Args;
use env_logger::Env;
use errors::*;
use link::DataLink;
use std::io::stdout;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime};
use structopt::StructOpt;
use chrono::{DateTime, Local, Utc};

fn main() -> Result<()> {
    env_logger::init_from_env(Env::default().default_filter_or("sniffglue=warn"));

    let mut args = Args::from_args();

    let device = if let Some(dev) = args.device {
        dev
    } else {
        sniff::default_interface().context("Failed to find default interface")?
    };

    let layout = if args.debugging {
        fmt::Layout::Debugging
    } else {
        fmt::Layout::Compact
    };

    let colors = atty::is(atty::Stream::Stdout);
    let config = fmt::Config::new(layout, args.verbose, colors);

    let cap = if !args.read {
        let cap = sniff::open(
            &device,
            &sniff::Config {
                promisc: args.promisc,
                immediate_mode: true,
            },
        )?;

        let verbosity = config.filter().verbosity;
        eprintln!(
            "Listening on device: {:?}, verbosity {}/4",
            device, verbosity
        );
        cap
    } else {
        if args.threads.is_none() {
            debug!("Setting thread default to 1 due to -r");
            args.threads = Some(1);
        }

        let cap = sniff::open_file(&device)?;
        eprintln!("Reading from file: {:?}", device);
        cap
    };

    let threads = args.threads.unwrap_or_else(num_cpus::get);
    debug!("Using {} threads", threads);

    let datalink = DataLink::from_linktype(cap.datalink())?;

    let filter = config.filter();
    let (tx, rx) = mpsc::sync_channel(256);
    let cap = Arc::new(Mutex::new(cap));

    for _ in 0..threads {
        let cap = cap.clone();
        let datalink = datalink.clone();
        let filter = filter.clone();
        let tx = tx.clone();
        thread::spawn(move || loop {
            let packet = {
                let mut cap = cap.lock().unwrap();
                cap.next_pkt()
            };

            if let Ok(Some(packet)) = packet {
                let ts = SystemTime::UNIX_EPOCH
                    + Duration::new(packet.ts.tv_sec as _, (packet.ts.tv_usec * 1000) as _);
                let packet = centrifuge::parse(&datalink, &packet.data);
                if filter.matches(&packet) {
                    tx.send((ts, packet)).unwrap()
                }
            } else {
                debug!("End of packet stream, shutting down reader thread");
                break;
            }
        });
    }
    drop(tx);

    let mut conn_map = flow::connection::ConnectionMap::new();
    let local_ip = "192.168.6.51".parse().unwrap();
    for (ts, packet) in rx.iter() {
        if let Some(data) = flow::extract_flow_data(&local_ip, ts, &packet) {
            conn_map.add(data);
        }
    }
    println!("{:-^100}", " connections ");
    let mut conn_list = vec![];
    for list in conn_map.map.values() {
        for conn in list.iter() {
            if conn.valid() {
                conn_list.push(conn.clone());
            }
        }
    }
    conn_list.sort_by(|a, b| {
        let a = a.ingress_tsrange().unwrap().0;
        let b = b.ingress_tsrange().unwrap().0;
        a.cmp(&b)
    });
    for conn in conn_list.iter() {
        let (ia, ib) = conn.ingress_tsrange().unwrap();
        let dia = DateTime::<Local>::from(ia);
        let dib = DateTime::<Local>::from(ib);
        let (ea, eb) = conn.egress_tsrange().unwrap();
        let dea = DateTime::<Local>::from(ea);
        let deb = DateTime::<Local>::from(eb);
        println!(
            "Time {} ~ {} {:>4} seconds / {} ~ {} {:>4} seconds:",
            dia.format("%H:%M:%S.%3f"),
            dib.format("%H:%M:%S.%3f"),
            ib.duration_since(ia).unwrap().as_secs(),
            dea.format("%H:%M:%S.%3f"),
            deb.format("%H:%M:%S.%3f"),
            eb.duration_since(ea).unwrap().as_secs(),
        );
        println!(
            "     {:20} <=> {:20} pkts={:>6} / {:<6} ssrc= 0x{:0^8X} / 0x{:0^8X}",
            conn.header.local,
            conn.header.remote,
            conn.ingress_pkts.len(),
            conn.egress_pkts.len(),
            conn.ingress_ssrc().unwrap(),
            conn.egress_ssrc().unwrap(),
        );
    }

    println!("{:-^100}", " calls ");
    let calls = flow::call::extract_calls(&conn_list);
    for c in calls.iter() {
        let stats = c.compute_stats();
        
        let (ia, ib) = c.peer1.ingress_tsrange().unwrap();
        let dia = DateTime::<Local>::from(ia);
        let dib = DateTime::<Local>::from(ib);
        println!(
            "Time {} ~ {} {:>4} seconds:",
            dia.format("%H:%M:%S.%3f"),
            dib.format("%H:%M:%S.%3f"),
            ib.duration_since(ia).unwrap().as_secs()
        );
        println!(
            "     {:20} <=> {:20}   ssrc:         0x{:08X} <=> 0x{:08X}",
            c.peer1.header.remote,
            c.peer2.header.remote,
            c.header.peer1_ssrc,
            c.header.peer2_ssrc
        );
        println!(
            "{} ingress_flow    forward: lost / max_delta_msec / max_interframe_msec",
            " ".repeat(30)
        );
        println!(
            "{}                      {:7.4}% / {:14} / {:19}",
            " ".repeat(30),
            stats.peer1_ingress_flow.lost_rate,
            stats.peer1_ingress_flow.max_delta / 1000,
            stats.peer1_ingress_flow.max_inter_frame_delay / 1000
        );
        println!(
            "{} ingress_flow   backward: lost / max_delta_msec / max_interframe_msec",
            " ".repeat(30)
        );
        println!(
            "{}                      {:7.4}% / {:14} / {:19}",
            " ".repeat(30),
            stats.peer2_ingress_flow.lost_rate,
            stats.peer2_ingress_flow.max_delta / 1000,
            stats.peer2_ingress_flow.max_inter_frame_delay / 1000
        );

        println!(
            "{} delay_usec      forward: avg /  max /    std",
            " ".repeat(30)
        );
        println!(
            "{}                         {:4} / {:4} /  {:5.2}",
            " ".repeat(30),
            stats.peer1_delay.avg,
            stats.peer1_delay.max,
            stats.peer1_delay.std
        );

        println!(
            "{} delay_usec     backward: avg /  max /    std",
            " ".repeat(30)
        );
        println!(
            "{}                         {:4} / {:4} /  {:5.2}",
            " ".repeat(30),
            stats.peer2_delay.avg,
            stats.peer2_delay.max,
            stats.peer2_delay.std,
        );
    }
    Ok(())
}
