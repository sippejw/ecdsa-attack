extern crate time;

use postgres::{Client, NoTls};

use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::Packet;
use pnet::packet::tcp::{TcpPacket, TcpFlags, ipv4_checksum, ipv6_checksum};

use std::collections::{HashSet, HashMap, VecDeque};
use std::net::IpAddr;
use std::ops::Sub;
use std::thread;
use std::time::{Duration, Instant};

use cache::{MeasurementCache, MEASUREMENT_CACHE_FLUSH};
use common::{TimedFlow, Flow};
use stats_tracker::StatsTracker;
use tls_parser;
use tls_structs::{CipherSuite, ClientHelloFingerprint, Primer, TlsAlert, ClientKeyExchange, TlsAlertLevel};

pub struct FlowTracker {
    flow_timeout: Duration,
    write_to_stdout: bool,
    write_to_db: bool,
    dsn: Option<String>,

    cache: MeasurementCache,

    pub stats: StatsTracker,

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
            return;
        }
        if (tcp_flags & TcpFlags::FIN) != 0 || (tcp_flags & TcpFlags::RST) != 0 {
            self.tracked_flows.remove(&flow);
            return;
        }
        if tcp_pkt.payload().len() == 0 {
            return
        }

        // check for ClientHello
        if is_client && self.tracked_flows.contains(&flow) {
            self.stats.fingerprint_checks += 1;
            match ClientHelloFingerprint::from_try(tcp_pkt.payload()) {
                Ok(fp) => {
                    self.stats.fingerprints_seen += 1;
                    let fp_id = fp.get_fingerprint();

                    let primer = Primer::new(fp.client_random.clone(), &source, &destination);

                    self.begin_tracking_server_flow(&flow.reversed_clone(), fp_id as i64);

                    let mut curr_time = time::now();

                    if self.write_to_stdout {
                        println!("ClientHello: {{ id: {} t: {} {}}}",
                                 fp_id, curr_time.to_timespec().sec, fp);
                    }

                    if self.write_to_db {
                        // once in a while -- flush everything
                        if curr_time.to_timespec().sec - self.cache.last_flush.to_timespec().sec >
                            MEASUREMENT_CACHE_FLUSH {
                            self.flush_to_db()
                        }

                        // insert primer
                        self.cache.add_primer(&flow, primer);

                        // insert size of session ticket, if any
                        fp.ticket_size.map(|size| self.cache.add_ticket_size(fp_id as i64, size));

                        // insert current fingerprint and measurement
                        self.cache.add_connection(&flow, fp_id as i64,
                                                  fp.sni.to_vec(), curr_time.to_timespec().sec);
                        self.cache.add_fingerprint(fp_id as i64, fp);

                        curr_time.tm_nsec = 0; // privacy
                        curr_time.tm_sec = 0;
                        curr_time.tm_min = 0;
                        self.cache.add_measurement(fp_id as i64, curr_time.to_timespec().sec as i32);
                    }
                }
                Err(err) => {
                    self.stats.store_clienthello_error(err);
                }
            }
            match TlsAlert::from_try(tcp_pkt.payload()) {
                Ok(alert) => {
                    self.cache.update_primer_with_alert(&flow, alert.description);
                    if alert.level == TlsAlertLevel::Fatal {
                        self.cache.update_primer_complete(&flow)
                    }
                }
                Err(err) => {println!("err: {:?}", err)}
            }
            match ClientKeyExchange::from_try(tcp_pkt.payload()) {
                Ok(cke) => {
                    self.cache.update_primer_complete(&flow);
                }
                Err(err) => {println!("err: {:?}", err)}
            }
            self.tracked_flows.remove(&flow);
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
            self.stats.sfingerprint_checks += 1;
            match tls_parser::from_try(tcp_pkt.payload(), &mut flow) {
                Ok(fp) => {
                    match fp.get_server_hello() {
                        Some(ref sh) => {
                            // replace flow with new overflow one
                            let cid = self.tracked_server_flows.remove(&flow).unwrap();
                            self.tracked_server_flows.insert(flow, cid);

                            self.stats.sfingerprints_seen += 1;
                            let sid = sh.get_fingerprint() as i64;
                            // let cid = self.tracked_server_flows[&flow];

                            if self.write_to_stdout {
                                println!("ServerHello: {{ sid: {} cid: {} sh: {}}}",
                                        sid, cid, sh);
                            }

                            // need to re-write this to handle that fp is now a general return
                            if self.write_to_db {
                                // self.cache.add_sfingerprint(sid, fp);
                                // self.cache.add_smeasurement(cid, sid);
                                // self.cache.update_connection_with_sid(&flow.reversed_clone(), sid);
                                self.cache.update_primer_with_cs_sr(&flow.reversed_clone(), sh.cipher_suite, sh.server_random.clone());
                            }
                        }
                        None => {}
                    }

                    match fp.get_certificate() {
                        Some(ref cert) => {
                            println!("Cert key: {:02x?}", cert.public_key().unwrap().public_key_to_der().unwrap());
                            // replace flow with new overflow one
                            self.cache.update_primer_with_cert(&flow.reversed_clone(), cert.clone().clone());
                            let cid = self.tracked_server_flows.remove(&flow).unwrap();
                            self.tracked_server_flows.insert(flow, cid);
                        }
                        None => {/*println!("got no cert");*/}

                    }

                    match fp.get_server_key_exchange() {
                        Some(ske) => {
                            println!("server key exchange: {}", ske);
                            self.cache.update_primer_with_sp(&flow.reversed_clone(), ske.server_params.clone());
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
        let client_mcache = self.cache.flush_measurements();
        let client_fcache = self.cache.flush_fingerprints();
        let server_mcache = self.cache.flush_smeasurements();
        let server_fcache = self.cache.flush_sfingerprints();
        let pcache = self.cache.flush_primers();
        let c4cache = self.cache.flush_ipv4connections();
        let c6cache = self.cache.flush_ipv6connections();
        let ticket_sizes = self.cache.flush_ticket_sizes();

        let dsn = self.dsn.clone().unwrap();
        thread::spawn(move || {
            let inserter_thread_start = time::now();
            let mut thread_db_conn = Client::connect(&dsn, NoTls).unwrap();

            let insert_fingerprint = match thread_db_conn.prepare(
                "INSERT
                INTO fingerprints (
                    id,
                    record_tls_version,
                    ch_tls_version,
                    cipher_suites,
                    compression_methods,
                    extensions,
                    named_groups,
                    ec_point_fmt,
                    sig_algs,
                    alpn,
                    key_share,
                    psk_key_exchange_modes,
                    supported_versions,
                    cert_compression_algs,
                    record_size_limit)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
                ON CONFLICT (id) DO NOTHING;")
            {
                Ok(stmt) => stmt,
                Err(e) => {
                    println!("Preparing insert_fingerprint failed: {}", e);
                    return;
                }
            };

            let insert_measurement = match thread_db_conn.prepare(
                "INSERT
                INTO measurements (unixtime, id, count)
                VALUES ($1, $2, $3)
                ON CONFLICT ON CONSTRAINT measurements_pkey1 DO UPDATE
                SET count = measurements.count + $4;")
            {
                Ok(stmt) => stmt,
                Err(e) => {
                    println!("Preparing insert_measurement failed: {}", e);
                    return;
                }
            };

            let insert_sfingerprint = match thread_db_conn.prepare(
                "INSERT
                INTO sfingerprints (id,
                    record_tls_version,
                    sh_tls_version,
                    cipher_suite,
                    compression_method,
                    extensions,
                    eliptic_curves,
                    ec_point_fmt,
                    alpn)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                ON CONFLICT (id) DO NOTHING;")
            {
                Ok(stmt) => stmt,
                Err(e) => {
                    println!("Preparing insert_sfingerprint failed: {}", e);
                    return;
                }
            };

            let insert_smeasurement = match thread_db_conn.prepare(
                "INSERT
                INTO smeasurements (cid, sid, count)
                VALUES ($1, $2, $3)
                ON CONFLICT ON CONSTRAINT smeasurements_pkey DO UPDATE
                SET count = smeasurements.count + $4;")
            {
                Ok(stmt) => stmt,
                Err(e) => {
                    println!("Preparing insert_smeasurement failed: {}", e);
                    return;
                }
            };

            let insert_ipv4conn = match thread_db_conn.prepare(
                "INSERT
                INTO ipv4connections (id, sid, anon_cli_ip, server_ip, SNI)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT DO NOTHING;")
            {
                Ok(stmt) => stmt,
                Err(e) => {
                    println!("Preparing insert_ipv4conn failed: {}", e);
                    return;
                }
            };

            let insert_ipv6conn = match thread_db_conn.prepare(
                "INSERT
                INTO ipv6connections (id, sid, anon_cli_ip, server_ip, SNI)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT DO NOTHING;")
            {
                Ok(stmt) => stmt,
                Err(e) => {
                    println!("Preparing insert_ipv6conn failed: {}", e);
                    return;
                }
            };

            let insert_ticket_size = match thread_db_conn.prepare(
                "INSERT
                INTO ticket_sizes (id, size, count)
                VALUES ($1, $2, $3)
                ON CONFLICT ON CONSTRAINT ticket_sizes_pkey DO UPDATE
                SET count = ticket_sizes.count + $4;")
            {
                Ok(stmt) => stmt,
                Err(e) => {
                    println!("Preparing insert_ticket_size failed: {}", e);
                    return;
                }
            };

            let insert_primer = match thread_db_conn.prepare(
                "INSERT
                INTO primers (
                    client_random,
                    server_random,
                    server_params,
                    server_ip,
                    client_ip,
                    cipher_suite,
                    is_alert)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                ON CONFLICT DO NOTHING;"
            )
            {
                Ok(stmt) => stmt,
                Err(e) => {
                    println!("Preparing insert_primer failed: {}", e);
                    return;
                }
            };

            for (fp_id, fp) in client_fcache {
                let updated_rows = thread_db_conn.execute(&insert_fingerprint, &[&(fp_id as i64),
                &(fp.record_tls_version as i16), &(fp.ch_tls_version as i16),
                &fp.cipher_suites, &fp.compression_methods, &fp.extensions,
                &fp.named_groups, &fp.ec_point_fmt, &fp.sig_algs, &fp.alpn,
                &fp.key_share, &fp.psk_key_exchange_modes, &fp.supported_versions,
                &fp.cert_compression_algs, &fp.record_size_limit,]);
                if updated_rows.is_err() {
                    println!("Error updating fingerprints: {:?}", updated_rows);
                }
            }

            for (k, count) in client_mcache {
                let updated_rows = thread_db_conn.execute(&insert_measurement, &[&(k.1), &(k.0),
                    &(count), &(count)]);
                if updated_rows.is_err() {
                    println!("Error updating measurements: {:?}", updated_rows);
                }
            }

            for (sid, fp) in server_fcache {
                let updated_rows = thread_db_conn.execute(&insert_sfingerprint, &[&(sid as i64),
                    &(fp.record_tls_version as i16), &(fp.sh_tls_version as i16),
                    &(fp.cipher_suite as i16), &(fp.compression_method as i8), &fp.extensions,
                    &fp.elliptic_curves, &fp.ec_point_fmt, &fp.alpn]);
                if updated_rows.is_err() {
                    println!("Error updating sfingerprints: {:?}", updated_rows);
                }
            }

            for (k, count) in server_mcache {
                let updated_rows = thread_db_conn.execute(&insert_smeasurement, &[&(k.0), &(k.1),
                    &(count), &(count)]);
                if updated_rows.is_err() {
                    println!("Error updating smeasurements: {:?}", updated_rows);
                }
            }

            for (k, primer) in pcache {
                let updated_rows = thread_db_conn.execute(&insert_primer, &[&(primer.client_random),
                    &(primer.server_random), &(primer.server_params), &(primer.server_ip),
                    &(primer.client_ip), &(primer.alert_message as i8),]);
                if updated_rows.is_err() {
                    println!("Error updating primers: {:?}", updated_rows)
                }
            }

            for ipv4c in c4cache {
                let updated_rows = thread_db_conn.execute(&insert_ipv4conn, &[&(ipv4c.id as i64), &(ipv4c.sid as i64),
                    &(ipv4c.anon_cli_ip), &(ipv4c.serv_ip), &(ipv4c.sni)]);
                if updated_rows.is_err() {
                    println!("Error updating ipv4connections: {:?}", updated_rows);
                }
            }

            for ipv6c in c6cache {
                let updated_rows = thread_db_conn.execute(&insert_ipv6conn, &[&(ipv6c.id as i64), &(ipv6c.sid as i64),
                    &(ipv6c.anon_cli_ip), &(ipv6c.serv_ip), &(ipv6c.sni)]);
                if updated_rows.is_err() {
                    println!("Error updating ipv6connections: {:?}", updated_rows);
                }
            }

            for (k, count) in ticket_sizes {
                let updated_rows = thread_db_conn.execute(&insert_ticket_size, &[&(k.0 as i64),
                    &(k.1 as i16), &(count), &(count)]);
                if updated_rows.is_err() {
                    println!("Error updating ticket sizes: {:?}", updated_rows);
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
