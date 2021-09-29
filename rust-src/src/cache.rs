extern crate time;

use std::collections::{HashSet, HashMap};
use common::{Flow, ConnectionIPv4, u8_to_u16_be, u8_to_u32_be, u8array_to_u32_be};
use std::net::IpAddr;
use tls_structs::{CipherSuite, Primer, TlsAlertMessage, TlsHandshakeType};
use stats_tracker::StatsTracker;

// to ease load on db, cache queries
pub struct MeasurementCache {
    pub last_flush: time::Tm,

    // for Primer
    primers_new: HashMap<Flow, Primer>,
    primers_flushed: HashSet<Flow>,
}

pub const MEASUREMENT_CACHE_FLUSH: i64 = 60; // every min
pub const CONNECTION_SID_WAIT_TIMEOUT: i64 = 10; // 10 secs

impl MeasurementCache {
    pub fn new() -> MeasurementCache {
        MeasurementCache {
            last_flush: time::now(),

            primers_flushed: HashSet::new(),
            primers_new: HashMap::new(),
        }
    }

    pub fn add_primer(&mut self, flow: &Flow, primer: Primer) {
        if !self.primers_flushed.contains(&flow) {
            self.primers_new.insert(*flow, primer);
        }
    }

    pub fn update_primer_server_hello(&mut self, flow: &Flow, cs: CipherSuite, sr: Vec<u8>)
    {
        match self.primers_new.get_mut(&flow) {
            Some(mut primer) => {
                primer.cipher_suite = cs as u16;
                primer.server_random = sr;
                primer.next_state = TlsHandshakeType::Certificate;
            },
            _ => {}
        }
    }

    pub fn update_primer_certificate(&mut self, flow: &Flow, pub_key: Vec<u8>, sig_alg: i32)
    {
        match self.primers_new.get_mut(&flow) {
            Some(mut primer) => {
                println!("Adding public key");
                primer.pub_key = pub_key;
                primer.sig_alg = sig_alg;
                primer.next_state = TlsHandshakeType::ServerKeyExchange;
            } ,
            _ => {}
        }
    }

    pub fn update_primer_ske(&mut self, flow: &Flow, sp: Vec<u8>, sig: Option<Vec<u8>>)
    {
        match self.primers_new.get_mut(&flow) {
            Some(mut primer) => {
                println!("Add server params");
                primer.server_params = sp;
                primer.signature = sig;
                primer.next_state = TlsHandshakeType::ClientKeyExchange;
            },
            _ => {}
        }
    }

    pub fn update_primer_with_alert(&mut self, flow: &Flow, message: TlsAlertMessage)
    {
        match self.primers_new.get_mut(&flow) {
            Some(mut primer) => primer.alert_message = message,
            _ => {}
        }
    }

    pub fn get_primer_state(&mut self, flow: &Flow) -> TlsHandshakeType
    {
        match self.primers_new.get(&flow) {
            Some(primer) => return primer.next_state.clone(),
            _ => return TlsHandshakeType::ClientHello
        }
    }

    pub fn update_primer_complete(&mut self, flow: &Flow) -> bool
    {
        match self.primers_new.get_mut(&flow) {
            Some(mut primer) => {
                primer.is_complete = true;
                return true;
            },
            _ => return false
        }
    }

    // Confirms primers is complete
    // Returns cached HashMap of primers to be added to db
    // Removes stale and ready primers
    pub fn flush_primers(&mut self) -> HashMap<Flow, Primer> {
        self.last_flush = time::now();
        let mut primers_ready = HashMap::new();
        let mut stale_primer_flows = HashSet::new();
        let curr_time = time::now().to_timespec().sec;
        for (flow, primer) in self.primers_new.iter() {
            if primer.is_complete == true {
                self.primers_flushed.insert(*flow);
                primers_ready.insert(*flow, primer.clone());
                stale_primer_flows.insert(*flow);
            }
            else if curr_time - primer.start_time > MEASUREMENT_CACHE_FLUSH {
                println!("Removing stale primer");
                stale_primer_flows.insert(*flow);
            }
        }
        for flow in stale_primer_flows {
            self.primers_new.remove(&flow);
        }
        return primers_ready;
    }
}
