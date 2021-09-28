extern crate time;

use std::collections::{HashSet, HashMap};
use common::{Flow, ConnectionIPv6, ConnectionIPv4, u8_to_u16_be, u8_to_u32_be, u8array_to_u32_be};
use std::net::IpAddr;
use tls_structs::{CipherSuite, Primer, TlsAlertMessage, TlsHandshakeType};
use stats_tracker::StatsTracker;

// to ease load on db, cache queries
pub struct MeasurementCache {
    pub last_flush: time::Tm,

    // for Primer
    primers_new: HashMap<Flow, Primer>,
    primers_flushed: HashSet<Flow>,

    // for connections
    ipv4_connections_seen: HashSet<(i64, u32)>,
    ipv4_connections: HashMap<Flow, ConnectionIPv4>,
    ipv6_connections: HashMap<Flow, ConnectionIPv6>,
}

pub const MEASUREMENT_CACHE_FLUSH: i64 = 60; // every min
pub const CONNECTION_SID_WAIT_TIMEOUT: i64 = 10; // 10 secs

impl MeasurementCache {
    pub fn new() -> MeasurementCache {
        MeasurementCache {
            last_flush: time::now(),

            primers_flushed: HashSet::new(),
            primers_new: HashMap::new(),

            ipv4_connections_seen: HashSet::new(),
            ipv4_connections: HashMap::new(),
            ipv6_connections: HashMap::new(),
        }
    }

    pub fn add_primer(&mut self, flow: &Flow, primer: Primer) {
        if !self.primers_flushed.contains(&flow) {
            self.primers_new.insert(flow.clone(), primer);
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

    pub fn add_connection(&mut self, flow: &Flow, cid: i64, sni: Vec<u8>, time_sec: i64) {
        match flow.src_ip {
            IpAddr::V4(ip_src) => {
                match flow.dst_ip {
                    IpAddr::V4(ip_dst) => {
                        let serv_ip = u8array_to_u32_be(ip_dst.octets());
                        if self.ipv4_connections_seen.contains(&(cid, serv_ip)) {
                            return
                        }
                        let c = ConnectionIPv4 {
                            anon_cli_ip: u8_to_u16_be(ip_src.octets()[0], ip_src.octets()[1]) as i16,
                            serv_ip: serv_ip,
                            id: cid,
                            sni: sni,
                            sid: 0,
                            time_sec: time_sec,
                        };
                        self.ipv4_connections.insert(flow.clone(), c);
                        self.ipv4_connections_seen.insert((cid, serv_ip));
                        return
                    }
                    IpAddr::V6(_) => {
                        println!("[WARNING] IP versions mismatch! source(ipv4): {}, destination(ipv6): {}",
                                 flow.src_ip, flow.dst_ip);
                    }
                }
            }
            IpAddr::V6(ip_src) => {
                match flow.dst_ip {
                    IpAddr::V6(ip_dst) => {
                        let c = ConnectionIPv6 {
                            anon_cli_ip: u8_to_u32_be(ip_src.octets()[0], ip_src.octets()[1],
                                                      ip_src.octets()[2], ip_src.octets()[3]),
                            serv_ip: ip_dst.octets().to_vec(),
                            id: cid,
                            sni: sni,
                            sid: 0,
                            time_sec: time_sec,
                        };
                        self.ipv6_connections.insert(flow.clone(), c);
                        return
                    }
                    IpAddr::V4(_) => {
                        println!("[WARNING] IP versions mismatch! source(ipv6): {}, destination(ipv4): {}",
                                 flow.src_ip, flow.dst_ip);
                    }
                }
            }
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
                self.primers_flushed.insert(flow.clone());
                primers_ready.insert(flow.clone(), primer.clone());
                stale_primer_flows.insert(flow.clone());
            }
            else if curr_time - primer.start_time > MEASUREMENT_CACHE_FLUSH {
                println!("Removing stale primer");
                stale_primer_flows.insert(flow.clone());
            }
        }
        for flow in stale_primer_flows {
            self.primers_new.remove(&flow);
        }
        return primers_ready;
    }

    fn get_ipv4connections_to_flush(&self) -> HashSet<Flow> {
        let mut hs_flows = HashSet::new();
        let curr_sec = self.last_flush.to_timespec().sec;
        for (flow, conn) in self.ipv4_connections.iter() {
            if conn.sid != 0 || curr_sec - conn.time_sec > CONNECTION_SID_WAIT_TIMEOUT {
                hs_flows.insert(flow.clone());
            }
        }
        hs_flows
    }

    // returns cached HashMap of ipv4 connections, empties it in object
    pub fn flush_ipv4connections(&mut self) -> HashSet<ConnectionIPv4> {
        self.last_flush = time::now();
        let mut hs_conns = HashSet::new();
        for flow in self.get_ipv4connections_to_flush() {
            hs_conns.insert(self.ipv4_connections.remove(&flow).unwrap());
        }
        hs_conns
    }

    fn get_ipv6connections_to_flush(&self) -> HashSet<Flow> {
        let mut hs_flows = HashSet::new();
        let curr_sec = self.last_flush.to_timespec().sec;
        for (flow, conn) in self.ipv6_connections.iter() {
            if conn.sid != 0 || curr_sec - conn.time_sec > CONNECTION_SID_WAIT_TIMEOUT {
                hs_flows.insert(flow.clone());
            }
        }
        hs_flows
    }

    // returns cached HashMap of ipv6 connections, empties it in object
    pub fn flush_ipv6connections(&mut self) -> HashSet<ConnectionIPv6> {
        self.last_flush = time::now();
        let mut hs_conns = HashSet::new();
        for flow in self.get_ipv6connections_to_flush() {
            hs_conns.insert(self.ipv6_connections.remove(&flow).unwrap());
        }
        hs_conns
    }
}
