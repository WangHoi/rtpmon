use structopt::StructOpt;
use structopt::clap::{AppSettings, Shell};

#[derive(Debug, StructOpt)]
#[structopt(global_settings = &[AppSettings::ColoredHelp])]
pub struct Args {
    #[structopt(short="p", long="promisc")]
    pub promisc: bool,
    #[structopt(long="debugging")]
    pub debugging: bool,
    /// Open a pcap file instead of a device
    #[structopt(short="r", long="read")]
    pub read: bool,
    // #[structopt(short="n", long="threads", alias="cpus")]
    // pub threads: Option<usize>,
    /// The device or file to read packets from
    pub device: Option<String>,
    #[structopt(short="v", long="verbose",
                parse(from_occurrences),
                help="Increase filter sensitivity to show more (possibly less useful) packets.
The default only shows few packets, this flag can be specified multiple times. (maximum: 4)")]
    pub verbose: u8,
    #[structopt(short="n", long="threads", alias="cpus")]
    pub threads: Option<usize>,
}
