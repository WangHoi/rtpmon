mod cli;
mod fmt;
mod sniff;
mod structs;
mod link;
mod errors;
mod centrifuge;
mod flow;

use errors::*;
use crate::cli::Args;
use env_logger::Env;
use link::DataLink;
use std::io::stdout;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use structopt::StructOpt;

fn main() -> Result<()> {
    env_logger::init_from_env(Env::default()
        .default_filter_or("sniffglue=warn"));

    let mut args = Args::from_args();

    let device = if let Some(dev) = args.device {
        dev
    } else {
        sniff::default_interface()
            .context("Failed to find default interface")?
    };

    let layout = if args.debugging {
        fmt::Layout::Debugging
    } else {
        fmt::Layout::Compact
    };

    let colors = atty::is(atty::Stream::Stdout);
    let config = fmt::Config::new(layout, args.verbose, colors);

    let cap = if !args.read {
        let cap = sniff::open(&device, &sniff::Config {
            promisc: args.promisc,
            immediate_mode: true,
        })?;

        let verbosity = config.filter().verbosity;
        eprintln!("Listening on device: {:?}, verbosity {}/4", device, verbosity);
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
        thread::spawn(move || {
            loop {
                let packet = {
                    let mut cap = cap.lock().unwrap();
                    cap.next_pkt()
                };

                if let Ok(Some(packet)) = packet {
                    let packet = centrifuge::parse(&datalink, &packet.data);
                    if filter.matches(&packet) {
                        tx.send(packet).unwrap()
                    }
                } else {
                    debug!("End of packet stream, shutting down reader thread");
                    break;
                }
            }
        });
    }
    drop(tx);

    let format = config.format();
    for packet in rx.iter() {
        format.print(packet);
    }

    Ok(())
}
