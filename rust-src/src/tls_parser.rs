extern crate num;
extern crate openssl;

use self::num::FromPrimitive;
use self::openssl::x509::X509;

use common::{Flow, ParseError, u8_to_u16_be, u8_to_u32_be};
use tls_structs::{CipherSuite, HasSignature, ServerCertificateParseResult, ServerHello, ServerHelloParseResult, 
    ServerKeyExchange, ServerKeyExchangeParseResult, ServerParseResult, ServerReturn, TlsHandshakeType, TlsRecordType, 
    TlsVersion};



// Coverts array of [u8] into Vec<u8>, and performs ungrease.
// Ungrease stores all greasy extensions/ciphers/etc under single id to produce single fingerprint
// https://tools.ietf.org/html/draft-davidben-tls-grease-01
pub fn ungrease_u8(arr: &[u8]) -> Vec<u8> {
    let mut res: Vec<u8> = arr.iter().cloned().collect();
    for i in 0..(arr.len() / 2) {
        if res[2 * i] == res[2 * i + 1] && (res[2 * i] & 0x0f == 0x0a) {
            res[2 * i] = 0x0a;
            res[2 * i + 1] = 0x0a;
        }
    }
    res
}

// parses groups and lengths of key_share (but not keys themselves) and ungreases the groups
// passed vector must already be stripped from overall size
pub fn parse_key_share(arr: &[u8]) -> Result<Vec<u8>, ParseError> {
    if arr.len() > std::u16::MAX as usize {
        return Err(ParseError::KeyShareExtLong);
    }
    let mut i: usize = 0;
    let mut res = Vec::new();
    while i < arr.len() {
        if i  > arr.len() - 4 {
            return Err(ParseError::KeyShareExtShort);
        }
        let mut group_size = ungrease_u8(&arr[i .. i+2]);
        let size = u8_to_u16_be(arr[i+2], arr[i+3]) as usize;
        group_size.push(arr[i+2]);
        group_size.push(arr[i+3]);
        res.append(&mut group_size);

        i = match i.checked_add(4 + size) {
            Some(i) => i,
            None => return Err(ParseError::KeyShareExtShort),
        };
    }
    Ok(res)
}

pub fn find_server_hello(a: &[u8], fl: &mut Flow) -> ServerHelloParseResult {
    let of = fl.overflow;
    if a.len() - 1 < of {
        return Err(ParseError::ShortBuffer);
    }

    let record_type = a[of];
    if TlsRecordType::from_u8(record_type) != Some(TlsRecordType::Handshake) {
        return Err(ParseError::NotAHandshake);
    }

    let record_tls_version = match TlsVersion::from_u16(u8_to_u16_be(a[of+1], a[of+2])) {
        Some(tls_version) => tls_version,
        None => return Err(ParseError::UnknownRecordTLSVersion),
    };

    let record_length = u8_to_u16_be(a[of+3], a[of+4]);
    if usize::from_u16(record_length).unwrap() > a.len() - 5 {
        return Err(ParseError::ShortOuterRecord);
    }

    // TODO: make this more general, not just parsing hellos anymore
    if TlsHandshakeType::from_u8(a[of+5]) != Some(TlsHandshakeType::ServerHello) {
        return Err(ParseError::NotAServerHello);
    }

    let ch_length = u8_to_u32_be(0, a[of+6], a[of+7], a[of+8]);
    if ch_length != record_length as u32 - 4 {
        return Err(ParseError::InnerOuterRecordLenContradict);
    }

    let sh_tls_version = match TlsVersion::from_u16(u8_to_u16_be(a[of+9], a[of+10])) {
        Some(tls_version) => tls_version,
        None => return Err(ParseError::UnknownChTLSVersion),
    };

    // 32 bytes of client random

    let mut offset: usize = of+11;
    let server_random = ungrease_u8(&a[offset..offset+32]);
    offset += 32;

    let session_id_len = a[offset] as usize;
    offset += session_id_len + 1;
    if offset + 2 > a.len() {
        return Err(ParseError::SessionIDLenExceedBuf);
    }

    if offset + 5 > a.len() {
        return Err(ParseError::ShortBuffer);
    }

    let cipher_suite = match CipherSuite::from_u16(u8_to_u16_be(a[offset], a[offset + 1])) {
        Some(cs) => cs,
        None => return Err(ParseError::NotACiphersuite),
    };

    fl.cipher_suite = cipher_suite;
    offset += 2;

    let compression_method = a[offset];
    offset += 1;


    let mut sh = ServerHello {
        record_tls_version: record_tls_version,
        sh_tls_version: sh_tls_version,
        server_random: server_random,
        cipher_suite: cipher_suite,
        compression_method: compression_method,
        extensions: Vec::new(),
        elliptic_curves: Vec::new(),
        ec_point_fmt: Vec::new(),
        alpn: Vec::new(),
    };

    let extensions_len = u8_to_u16_be(a[offset], a[offset + 1]) as usize;
    offset += 2;
    if offset + extensions_len > a.len() {
        return Err(ParseError::ExtensionsLenExceedBuf);
    }

    let sh_end = offset + extensions_len;
    while offset < sh_end {
        if offset > sh_end - 4 {
            return Err(ParseError::ShortExtensionHeader);
        }

        let ext_len = u8_to_u16_be(a[offset + 2], a[offset + 3]) as usize;
        if offset + ext_len > sh_end {
            return Err(ParseError::ExtensionLenExceedBuf);
        }
        sh.process_extension(&a[offset..offset + 2], &a[offset + 4..offset + 4 + ext_len]);

        offset = match (offset + 4).checked_add(ext_len) {
            Some(i) => i,
            None => return Err(ParseError::ExtensionLenExceedBuf),
        };
    }

    fl.overflow = of+offset;

    Ok(sh)
}

pub fn find_certificate(a: &[u8], fl: &mut Flow) -> ServerCertificateParseResult {
    let of = fl.overflow;
    if a.len() - 1 < of {
        return Err(ParseError::ShortBuffer);
    }

    let record_type = a[of];
    if TlsRecordType::from_u8(record_type) != Some(TlsRecordType::Handshake) {
        return Err(ParseError::NotAHandshake);
    }

    let _record_tls_version = match TlsVersion::from_u16(u8_to_u16_be(a[of+1], a[of+2])) {
        Some(tls_version) => tls_version,
        None => return Err(ParseError::UnknownRecordTLSVersion),
    };

    let record_length = u8_to_u16_be(a[of+3], a[of+4]);
    if usize::from_u16(record_length).unwrap() > a[of..].len() - 5 {
        // have an overflow of certs between packets
        fl.overflow = record_length as usize - a[of+5..].len();
    }

    if TlsHandshakeType::from_u8(a[of+5]) != Some(TlsHandshakeType::Certificate) {
        return Err(ParseError::NotACertificate);
    }

    let ch_length = u8_to_u32_be(0, a[of+6], a[of+7], a[of+8]);
    if ch_length != record_length as u32 - 4 {
        return Err(ParseError::InnerOuterRecordLenContradict);
    }
    let cert_len = u8_to_u32_be(0, a[of+12], a[of+13], a[of+14]) as usize;

    if a[of+15..].len() < cert_len {
        return Err(ParseError::NotFullCertificate);
    }

    // we have a full certificate here

    match X509::from_der(&a[of+15..of+15+cert_len]) {
        Ok(cert) => Ok(cert),
        Err(_) => Err(ParseError::NotACertificate),
    }
}

pub fn find_server_key_exchange(a: &[u8], fl: &mut Flow) -> ServerKeyExchangeParseResult {
    let mut of = fl.overflow;
    if a.len() - 1 < of {
        return Err(ParseError::ShortBuffer);
    }

    let record_type = a[of];
    if TlsRecordType::from_u8(record_type) != Some(TlsRecordType::Handshake) {
        return Err(ParseError::NotAHandshake);
    }

    let _record_tls_version = match TlsVersion::from_u16(u8_to_u16_be(a[of+1], a[of+2])) {
        Some(tls_version) => tls_version,
        None => return Err(ParseError::UnknownRecordTLSVersion),
    };

    let record_length = u8_to_u16_be(a[of+3], a[of+4]);

    if TlsHandshakeType::from_u8(a[of+5]) != Some(TlsHandshakeType::ServerKeyExchange) {
        return Err(ParseError::NoServerKeyExchange);
    }

    let ch_length = u8_to_u32_be(0, a[of+6], a[of+7], a[of+8]);
    if ch_length != record_length as u32 - 4 {
        return Err(ParseError::InnerOuterRecordLenContradict);
    }

    // what is collected here will depend on the type of algorithm selected, for now will only work for
    // ECDHE named curve
    
    //beginning of data
    of = of+9;

    // for ECDHE there is one byte for the type of curve to follow, for now only implement named_curve (0x03)

    let mut params: Vec<u8> = Vec::new();
    params.push(a[of]);
    match a[of] {
        0x03 => {params.extend(a[of+1..of+3].iter());}
        _ => {
            println!("unknown type of curve");
            return Err(ParseError::UnImplementedCurveType);
        }
    }

    // now append the public key, which will include the key length
    params.push(a[of+3]); // public key length
    if a[of+4..].len() < a[of+3] as usize {
        println!("Packet doesn't have full server key exchange");
        return Err(ParseError::ShortBuffer);
    }
    // this will have all of server key exchange so we have no more overflow on this flow
    fl.overflow = 0;
    params.extend(a[of+4..of+4+a[of+3] as usize].iter());// all of public key
    // (ec)dh(e)_rsa has a signature, we know whether it was selected from server hello
    of += 4 + a[of+3] as usize;

    let sig: Option<Vec<u8>>;
    match HasSignature::from_u16(fl.cipher_suite as u16) {
        Some(_hs) => {
            let mut tmp_sig: Vec<u8> = Vec::new();
            tmp_sig.extend(a[of..of+2].iter());
            let sig_len = u8_to_u16_be(a[of+2], a[of+3]) as usize;
            tmp_sig.extend(a[of+2..of+2+sig_len+2].iter()); // extra two bytes is to include the length of signature
            sig = Some(tmp_sig);
        }
        None => {
            sig = None;
        }
    }

    let ske = ServerKeyExchange {
        server_params: params,
        signature: sig,
    };

    Ok(ske)

}

pub fn from_try(a: &[u8], fl: &mut Flow) -> ServerParseResult {
    // not as important for general check.

    let mut sr = ServerReturn {
        server_hello: None,
        cert: None,
        server_key_exchange: None,
    };

    // first check for a ServerHello:
    match find_server_hello(a, fl) {
        Ok(sh) => {
            sr.server_hello = enum_primitive::Option::Some(sh);
        }
        Err(_) => {} // didn't find server hello
    }
    
    // now check for other records!

    match find_certificate(a, fl) {
        Ok(cert) => {
            sr.cert = enum_primitive::Option::Some(cert);
        }
        Err(_) => {} // didn't find a certificate
    }

    match find_server_key_exchange(a, fl) {
        Ok(ske) => {
            sr.server_key_exchange = enum_primitive::Option::Some(ske);
        }
        Err(_) => {} // didn't find a server key exchange 
    }
    Ok(sr)
}
