
extern crate pnet;


use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;

use pcap::Capture;

use std::ffi::CStr;
use std::net::IpAddr;
use std::os::raw::c_char;
use std::path::Path;

#[no_mangle]
pub extern fn tlsparse_handle_packets(packet_bytes: &[u8], len: u32){
    println!("hello from rust");
    println!("{} bytes received", len);

    let ethernet = EthernetPacket::new(packet_bytes);
    
    match ethernet.is_none() {
        false => {
            handle_ethernet_frame(&ethernet.unwrap());
        }
        true => {
            println!("Could not parse bytes as ethernet Frame");
        }
    }
}


#[no_mangle]
pub extern fn tlsparse_handle_pcap(file_name: *const c_char){
    let pcap_fname = unsafe { CStr::from_ptr(file_name) };

    match pcap_fname.to_str() {
        Ok(pcap_str) => {
            handle_pcap(pcap_str);
        }
        Err(_) => {
            println!("File name string not provided");
        }
    }
}


fn handle_pcap(pcap_str: &str){
    let path = Path::new(pcap_str);

    match Capture::from_file(&path) {
        Ok(mut cap) => {
            while let Ok(packet) = cap.next() {
                // println!("received packet! {:?}", packet);

                // Unwrap may be unsage here if from_file fails -- TODO
                let ethernet = EthernetPacket::new(packet.data).unwrap();

                handle_ethernet_frame(&ethernet);
            }
        }
        Err(_) => {
            println!("Error Parsing PCAP file");
        }
    }
}


fn handle_ethernet_frame(ethernet: &EthernetPacket) {
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => handle_ipv4_packet(ethernet),
        EtherTypes::Ipv6 => handle_ipv6_packet(ethernet),
        _ => println!(
            "Non IP packet: {} > {}; ethertype: {:?} length: {}",
            ethernet.get_source(),
            ethernet.get_destination(),
            ethernet.get_ethertype(),
            ethernet.packet().len()
        ),
    }
}

fn handle_ipv4_packet(ethernet: &EthernetPacket) {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        if header.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
            handle_tcp_packet(
                IpAddr::V4(header.get_source()),
                IpAddr::V4(header.get_destination()),
                header.payload(),
            );
        } else {
            println!("Non-TCP Packet -->  No TLS");
        }
    } else {
        println!("Malformed IPv4 Packet");
    }
}

fn handle_ipv6_packet(ethernet: &EthernetPacket) {
    let header = Ipv6Packet::new(ethernet.payload());
    if let Some(header) = header {
        if header.get_next_header() == IpNextHeaderProtocols::Tcp {
            handle_tcp_packet(
                IpAddr::V6(header.get_source()),
                IpAddr::V6(header.get_destination()),
                header.payload(),
            );
        } else {
            println!("Non-TCP Packet -->  No TLS");
        }
    } else {
        println!("Malformed IPv6 Packet");
    }
}



fn handle_tcp_packet(source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let tcp = TcpPacket::new(packet);
    if let Some(tcp) = tcp {
        println!(
            "TCP Packet: {}:{} > {}:{}; length: {}",
            source,
            tcp.get_source(),
            destination,
            tcp.get_destination(),
            packet.len(),
        );

        // Arbitrary number larger than packet size
        let application = tcp.payload();
        if application.len() > 0 { 
            if is_tls_packet(application[0]) { 
                handle_tls_packet(application);
            } else {
                // println!("Not TLS");
            }
        } else {
            // println!("No Payload");
        }
    } else {
        println!("Malformed TCP Packet");
    }
    println!();
}


fn handle_tls_packet(payload: &[u8]) {
    // parse client or server random 
    if payload[5] == 0x01 {
        if slice_to_len(&payload[6..9]) > payload.len(){
           println!(" --> Something's wrong"); 
        } else {
            println!("Client Hello: {:?}", &payload[10..42]);
        }
    } else if payload[5] == 0x02 {
        if slice_to_len(&payload[6..9]) > payload.len(){
           println!(" --> Something's wrong"); 
        } else {
            println!("Server Hello: {:?}", &payload[10..42]);
        }
    } else {
        println!("BOO"); 
    }
}


fn slice_to_len(slice: &[u8]) -> usize{
    let len = slice.len() - 1;
    let mut res = 0;
    for (i, &b) in slice.iter().enumerate() {
        res |= (b as u32) << ( 8*(len-i) as u32 );
    } 
    // println!("{}", res); // Debug
    return res as usize;
}


fn is_tls_packet(a: u8) -> bool {
    match a {
        20 | 21 | 22 | 23 | 255 => { return true; }
        _ => { return false; }
    }
}


/*===============================[ Testing ]=================================*/

#[cfg(test)]
mod tests {

    use super::*;  // make all private functions available to testing functions. 

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn test_pcap_parse() {
        handle_pcap("./data/tls-capture-ecdhe-rsa-pkcs1-sha256.pcap.pcapng");
    }

}


