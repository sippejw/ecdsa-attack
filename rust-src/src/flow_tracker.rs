extern crate time;

use postgres::{Client, NoTls};

use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::Packet;
use pnet::packet::tcp::{TcpPacket, TcpFlags, ipv4_checksum, ipv6_checksum};

use std::collections::{HashSet, HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::ops::Sub;
use std::thread;
use std::time::{Duration, Instant};

use cache::{MeasurementCache, MEASUREMENT_CACHE_FLUSH};
use common::{TimedFlow, Flow, u8array_to_u32_be};
use stats_tracker::StatsTracker;
use tls_parser;
use tls_structs::{CipherSuite, ClientHello, Primer, TlsAlert, ClientKeyExchange, TlsAlertLevel, TlsHandshakeType};

use crate::tls_structs::TCPRemainder;

pub struct FlowTracker {
    flow_timeout: Duration,
    write_to_stdout: bool,
    write_to_db: bool,
    dsn: Option<String>,

    cache: MeasurementCache,

    pub stats: StatsTracker,

    tracked_tcp_remainders: HashMap<Flow, TCPRemainder>,

    // Keys present in this set are flows we parse ClientHello from
    tracked_flows: HashSet<Flow>,
    stale_drops: VecDeque<TimedFlow>,

    // Keys present in this map are flows we parse ServerHello from
    tracked_server_flows: HashMap<Flow, i64>,
    stale_server_drops: VecDeque<TimedFlow>,
}

impl FlowTracker {
    pub fn new() -> FlowTracker {
        FlowTracker {
            flow_timeout: Duration::from_secs(20),
            tracked_tcp_remainders: HashMap::new(),
            tracked_flows: HashSet::new(),
            stale_drops: VecDeque::with_capacity(65536),
            tracked_server_flows: HashMap::new(),
            stale_server_drops: VecDeque::with_capacity(65536),
            write_to_stdout: true,
            write_to_db: false,
            cache: MeasurementCache::new(),
            stats: StatsTracker::new(),
            dsn: None,
        }
    }

    pub fn new_db(dsn: String, core_id: i8, total_cores: i32) -> FlowTracker {
        // TODO: (convinience) try to connect to DB and run any query, verifying credentials
        // right away

        let mut ft = FlowTracker {
            flow_timeout: Duration::from_secs(20),
            tracked_tcp_remainders: HashMap::new(),
            tracked_flows: HashSet::new(),
            stale_drops: VecDeque::with_capacity(65536),
            tracked_server_flows: HashMap::new(),
            stale_server_drops: VecDeque::with_capacity(65536),
            write_to_stdout: false,
            write_to_db: true,
            cache: MeasurementCache::new(),
            stats: StatsTracker::new(),
            dsn: Some(dsn),
        };
        // flush to db at different time on different cores
        ft.cache.last_flush = ft.cache.last_flush.sub(time::Duration::seconds(
            (core_id as i64) * MEASUREMENT_CACHE_FLUSH / (total_cores as i64)));
        ft
    }

    pub fn handle_ipv4_packet(&mut self, eth_pkt: &EthernetPacket) {
        self.stats.all_packets_total += 1;
        self.stats.bytes_processed += eth_pkt.packet().len() as u64;
        let ipv4_pkt = Ipv4Packet::new(eth_pkt.payload());
        if let Some(ipv4_pkt) = ipv4_pkt {
            match ipv4_pkt.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp => {
                    // taking not the whole payload is a work around PF_RING giving padding as data
                    //  ^^^ This was causing an overflow 
                    if let Some(tcp_pkt) = TcpPacket::new(&ipv4_pkt.payload()) {
                        if ipv4_checksum(&tcp_pkt, &ipv4_pkt.get_source(), &ipv4_pkt.get_destination()) ==
                            tcp_pkt.get_checksum() || true {
                            self.handle_tcp_packet(
                                IpAddr::V4(ipv4_pkt.get_source()),
                                IpAddr::V4(ipv4_pkt.get_destination()),
                                &tcp_pkt,
                            )
                        } else {
                            self.stats.bad_checksums += 1;
                        }
                    }
                }
                _ => return,
            }
        }
    }

    pub fn handle_ipv6_packet(&mut self, eth_pkt: &EthernetPacket) {
        self.stats.all_packets_total += 1;
        self.stats.bytes_processed += eth_pkt.packet().len() as u64;
        let ipv6_pkt = Ipv6Packet::new(eth_pkt.payload());
        if let Some(ipv6_pkt) = ipv6_pkt {
            match ipv6_pkt.get_next_header() {
                IpNextHeaderProtocols::Tcp => {
                    if let Some(tcp_pkt) = TcpPacket::new(ipv6_pkt.payload()) {
                        if ipv6_checksum(&tcp_pkt, &ipv6_pkt.get_source(), &ipv6_pkt.get_destination()) ==
                            tcp_pkt.get_checksum() {
                            self.handle_tcp_packet(
                                IpAddr::V6(ipv6_pkt.get_source()),
                                IpAddr::V6(ipv6_pkt.get_destination()),
                                &tcp_pkt,
                            )
                        } else {
                            self.stats.bad_checksums += 1;
                        }
                    }
                }
                _ => return,
            }
        }
    }

    fn handle_tcp_packet(&mut self, source: IpAddr, destination: IpAddr, tcp_pkt: &TcpPacket) {
        let is_client;
        if tcp_pkt.get_destination() == 443 {
            is_client = true;
        } else if tcp_pkt.get_source() == 443 {
            is_client = false;
        } else {
            return
        }
        let mut flow = Flow::new(&source, &destination, &tcp_pkt, 0, CipherSuite::TlsNullWithNullNull);
        let tcp_flags = tcp_pkt.get_flags();
        if (tcp_flags & TcpFlags::SYN) != 0 && (tcp_flags & TcpFlags::ACK) == 0 {
            self.begin_tracking_flow(&flow, tcp_pkt.packet().to_vec());
            let tcp_remainder = TCPRemainder::new();
            self.tracked_tcp_remainders.insert(flow, tcp_remainder);
            return;
        }
        if (tcp_flags & TcpFlags::FIN) != 0 || (tcp_flags & TcpFlags::RST) != 0 {
            self.tracked_flows.remove(&flow);
            self.tracked_tcp_remainders.remove(&flow);
            return;
        }
        if tcp_pkt.payload().len() == 0 {
            return
        }

        // check for ClientHello
        if is_client && self.tracked_flows.contains(&flow) {
            let next_state = self.cache.get_primer_state(&flow);
            match next_state {
                TlsHandshakeType::ClientKeyExchange => {
                    match ClientKeyExchange::from_try(tcp_pkt.payload()) {
                        Ok(_cke) => {
                            if self.cache.update_primer_complete(&flow) {
                                self.stats.primers_completed += 1;
                            }
                            self.tracked_flows.remove(&flow);
                            self.tracked_tcp_remainders.remove(&flow);
                        }
                        // If not Client Key Exchange, try TLS Alert
                        Err(err) => {
                            match TlsAlert::from_try(tcp_pkt.payload()) {
                                Ok(alert) => {
                                    self.cache.update_primer_with_alert(&flow, alert.description);
                                    if alert.level == TlsAlertLevel::Fatal {
                                        if self.cache.update_primer_complete(&flow) {
                                            self.stats.primers_completed += 1;
                                        }
                                        self.tracked_flows.remove(&flow);
                                        self.tracked_tcp_remainders.remove(&flow);
                                    }
                                }
                                // If not TLS Alert, send original error message
                                Err(_err) => {println!("err: {:?}", err)}
                            }
                        }
                    }
                }
                // If no Primer exists we start Client Hello
                TlsHandshakeType::ClientHello => {
                    match ClientHello::from_try(tcp_pkt.payload()) {
                        Ok(fp) => {
                            self.stats.primers_created += 1;
                            let mut addr = None;
                            match source {
                                IpAddr::V4(serv_ip) => {
                                    addr = Some(u8array_to_u32_be(serv_ip.octets()));
                                }
                                _ => {}
                            }
                            let primer = Primer::new(addr, fp.client_random.clone());

                            self.begin_tracking_server_flow(&flow.reversed_clone(), primer.id as i64);

                            let curr_time = time::now();
                            // insert primer
                            self.cache.add_primer(&flow, primer);
                            if self.write_to_db {
                                // once in a while -- flush everything
                                if curr_time.to_timespec().sec - self.cache.last_flush.to_timespec().sec >
                                    MEASUREMENT_CACHE_FLUSH {
                                    self.flush_to_db()
                                }
                            }
                        }
                        Err(err) => {
                            self.stats.store_clienthello_error(err);
                        }
                    }
                }

                // Any other types we'll defer. Cache will clear stale primers
                _ => {}
            }
            return;
        }

        // check for ServerHello
        if !is_client && self.tracked_server_flows.contains_key(&flow) {
            // reassign flow to get the one with the correct overflow & cipher_suite
            for (&key, _) in self.tracked_server_flows.iter() {
                if key == flow {
                    flow = key;
                    break;
                }
            }
            let tcp_remainder = self.tracked_tcp_remainders.get_mut(&flow.reversed_clone());

            match tls_parser::from_try(tcp_pkt.payload(), &mut flow, &mut tcp_remainder.unwrap()) {
                Ok(fp) => {
                    match fp.get_server_hello() {
                        Some(ref sh) => {
                            // replace flow with new overflow one
                            let cid = self.tracked_server_flows.remove(&flow).unwrap();
                            self.tracked_server_flows.insert(flow, cid);

                            self.cache.update_primer_server_hello(&flow.reversed_clone(), sh.cipher_suite, sh.server_random.clone());
                        }
                        None => {}
                    }

                    match fp.get_certificate() {
                        Some(ref cert) => {
                            let sig_alg = cert.signature_algorithm().object().nid().as_raw();
                            let pub_key = cert.public_key().unwrap().public_key_to_der().unwrap();
                            // replace flow with new overflow one
                            self.cache.update_primer_certificate(&flow.reversed_clone(), pub_key, sig_alg);
                            let cid = self.tracked_server_flows.remove(&flow).unwrap();
                            self.tracked_server_flows.insert(flow, cid);
                        }
                        None => {/*println!("got no cert");*/}

                    }

                    match fp.get_server_key_exchange() {
                        Some(ske) => {
                            println!("server key exchange: {}", ske);
                            self.cache.update_primer_ske(&flow.reversed_clone(), ske.server_params.clone(), ske.signature.clone());
                            self.tracked_server_flows.remove(&flow);
                        }

                        None => {/*println!("no server key exchange");*/}
                    }
                }
                Err(err) => {println!("err: {:?}", err)}
            }
        }
    }

    fn flush_to_db(&mut self) {
        let pcache = self.cache.flush_primers();

        let dsn = self.dsn.clone().unwrap();
        thread::spawn(move || {
            let inserter_thread_start = time::now();
            let mut thread_db_conn = Client::connect(&dsn, NoTls).unwrap();

            let insert_primer = match thread_db_conn.prepare(
                "INSERT
                INTO primers (
                    server_ip,
                    client_random,
                    server_random,
                    server_params,
                    cipher_suite,
                    tls_alert,
                    pub_key,
                    signature,
                    sig_alg)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                ON CONFLICT DO NOTHING;"
            )
            {
                Ok(stmt) => stmt,
                Err(e) => {
                    println!("Preparing insert_primer failed: {}", e);
                    return;
                }
            };

            for (_k, primer) in pcache {
                let updated_rows = thread_db_conn.execute(&insert_primer, &[&(primer.server_ip), &(primer.client_random),
                    &(primer.server_random), &(primer.server_params), &(primer.cipher_suite as i16), &(primer.alert_message as i8), &(primer.pub_key), &(primer.signature), &(primer.sig_alg)]);
                if updated_rows.is_err() {
                    println!("Error updating primers: {:?}", updated_rows)
                }
            }

            let inserter_thread_end = time::now();
            println!("Updating DB took {:?} ns in separate thread",
                     inserter_thread_end.sub(inserter_thread_start).num_nanoseconds());
        });
    }

    fn begin_tracking_flow(&mut self, flow: &Flow, _syn_data: Vec<u8>) {
        // Always push back, even if the entry was already there. Doesn't hurt
        // to do a second check on overdueness, and this is simplest.
        self.stale_drops.push_back(TimedFlow {
            event_time: Instant::now(),
            flow: *flow,
        });
        self.tracked_flows.insert(*flow);
    }

    fn begin_tracking_server_flow(&mut self, flow: &Flow, cid: i64) {
        // Always push back, even if the entry was already there. Doesn't hurt
        // to do a second check on overdueness, and this is simplest.
        self.stale_server_drops.push_back(TimedFlow {
            event_time: Instant::now(),
            flow: *flow,
        });
        self.tracked_server_flows.insert(*flow, cid);
    }

    // not called internally, has to be called externally
    pub fn cleanup(&mut self) {
        while !self.stale_drops.is_empty() && // is_empty: condition for unwraps
            self.stale_drops.front().unwrap().event_time.elapsed() >= self.flow_timeout {
            let cur = self.stale_drops.pop_front().unwrap();
            self.tracked_flows.remove(&cur.flow);
        }
        while !self.stale_server_drops.is_empty() && // is_empty: condition for unwraps
            self.stale_server_drops.front().unwrap().event_time.elapsed() >= self.flow_timeout {
            let cur = self.stale_server_drops.pop_front().unwrap();
            self.tracked_server_flows.remove(&cur.flow);
        }
    }

    pub fn debug_print(&mut self) {
        println!("[DEBUG] tracked_flows: {} stale_drops: {} \
                tracked_server_flows: {}, stale_server_drops: {}",
                 self.tracked_flows.len(), self.stale_drops.len(),
                 self.tracked_server_flows.len(), self.stale_server_drops.len());
        self.stats.print_avg_stats();
    }
}
