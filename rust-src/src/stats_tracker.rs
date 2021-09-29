extern crate time;

use std::ops::Sub;
use common::{ParseError};

pub struct StatsTracker {
    pub last_print: time::Tm,
    pub primers_created: u64,
    pub primers_completed: u64,

    pub all_packets_total: u64,
    pub bad_checksums: u64,
    pub bytes_processed: u64,
    pub not_a_clienthello: u64,
    pub extension_misparsed: u64,
    pub client_hello_misparsed: u64,
    pub not_a_client_key_exchange: u64,
    pub alert_misparsed: u64,
    pub primer_misparsed: u64,
}

impl StatsTracker {
    pub fn new() -> StatsTracker {
        StatsTracker {
            last_print: time::now(),
            primers_created: 0,
            primers_completed: 0,
            all_packets_total: 0,
            bad_checksums: 0,
            bytes_processed: 0,
            not_a_clienthello: 0,
            extension_misparsed: 0,
            client_hello_misparsed: 0,
            not_a_client_key_exchange: 0,
            alert_misparsed: 0,
            primer_misparsed: 0,
        }
    }

    pub fn print_avg_stats(&mut self) {
        let curr_time = time::now();
        let diff = curr_time.sub(self.last_print);
        let diff_float = match diff.num_nanoseconds() {
            Some(diff_float) => diff_float as f64 * 0.000000001,
            None => {
                println!("[WARNING] stats time diff is too big!");
                return
            }
        };
        if diff_float < 10e-3 {
            println!("[WARNING] print stats slower!");
            return
        }

        const BYTES_TO_GBPS: f64 = (1000 * 1000 * 1000 / 8) as f64;

        let _percent_misparsed;
        if self.primers_created != 0 {
            _percent_misparsed = self.client_hello_misparsed as f64 / self.primers_created as f64;
        } else {
            _percent_misparsed = 0 as f64;
        }

        println!("[STATS] primers: found {:.2} with {:.2} completed; \
         not a CH: {:.2} misparsed CH: {:.2} misparsed extension: {:2}; \
         packets: {:.2} (bad_checksums: {:.2}); Gbps: {:.4}",
                 self.primers_created as f64 / diff_float,
                 self.primers_completed as f64 / diff_float,
                 self.not_a_clienthello as f64 / diff_float,
                 self.client_hello_misparsed as f64 / diff_float,
                 self.extension_misparsed as f64 / diff_float,
                 self.all_packets_total as f64 / diff_float,
                 self.bad_checksums as f64 / diff_float,
                 self.bytes_processed as f64 / (BYTES_TO_GBPS * diff_float),
        );

        self.primers_created = 0;
        self.primers_completed = 0;
        self.all_packets_total = 0;
        self.bad_checksums = 0;
        self.bytes_processed = 0;
        self.not_a_clienthello = 0;
        self.extension_misparsed = 0;
        self.client_hello_misparsed = 0;

        self.last_print = curr_time;
    }

    pub fn store_clienthello_error(&mut self, err: ParseError) {
        match err {
            ParseError::ShortBuffer |
            ParseError::NotAHandshake |
            ParseError::UnknownRecordTLSVersion |
            ParseError::ShortOuterRecord |
            ParseError::NotAClientHello => {
                self.not_a_clienthello += 1;
            }
            ParseError::InnerOuterRecordLenContradict |
            ParseError::UnknownChTLSVersion |
            ParseError::SessionIDLenExceedBuf |
            ParseError::CiphersuiteLenMisparse |
            ParseError::CompressionLenExceedBuf |
            ParseError::ExtensionsLenExceedBuf |
            ParseError::ShortExtensionHeader |
            ParseError::ExtensionLenExceedBuf => {
                self.client_hello_misparsed += 1;
            }
            ParseError::KeyShareExtShort |
            ParseError::KeyShareExtLong |
            ParseError::KeyShareExtLenMisparse |
            ParseError::PskKeyExchangeModesExtShort |
            ParseError::PskKeyExchangeModesExtLenMisparse |
            ParseError::SupportedVersionsExtLenMisparse => {
                println!("{:?}", err);
                self.extension_misparsed += 1;
            }
            ParseError::NotAClientKeyExchange => {
                println!("{:?}", err);
                self.not_a_client_key_exchange += 1;
            }
            ParseError::NotAnAlert |
            ParseError::UnknownAlertLevel |
            ParseError::UnknownAlertMessage => {
                println!("{:?}", err);
                self.alert_misparsed += 1;
            }
            ParseError::NotAServerHello => {
                panic!("Got NotAServerHello error from parsing ClientHello")
            }
            ParseError::NotACertificate | ParseError::NotFullCertificate | ParseError::NoCertificateStatus => {
                panic!("Got NotACertificate error from parsing ClientHello")
            }
            ParseError::NoServerKeyExchange => {
                panic!("Got NoServerKeyExchange error from parsing ClientHello")
            }
            ParseError::UnImplementedCurveType => {
                panic!("Got UnImplementedCurveType error from parsing ClientHello")
            }
            ParseError::NotACiphersuite => {
                panic!("Got NotACiphersuite error from parsing ClientHello")
            }
        }
    }
}