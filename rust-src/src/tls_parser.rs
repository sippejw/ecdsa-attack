extern crate byteorder;
extern crate crypto;
extern crate hex_slice;
extern crate num;
extern crate openssl;

use self::byteorder::{ByteOrder, BigEndian};
use self::crypto::digest::Digest;
use self::crypto::sha1::Sha1;
use self::hex_slice::AsHex;
use self::num::FromPrimitive;
use self::openssl::x509::X509;

use std::fmt;
use std::hash::{Hash, Hasher};
use std::str;

use common::{u8_to_u16_be, u8_to_u32_be, vec_u8_to_vec_u16_be, hash_u32, ParseError};
use flow_tracker::FlowTracker;

enum_from_primitive! {
#[repr(u8)]
#[derive(PartialEq)]
pub enum TlsRecordType {
	ChangeCipherSpec = 20,
	Alert            = 21,
	Handshake        = 22,
	ApplicationData  = 23,
	Heartbeat        = 24,
}
}

enum_from_primitive! {
#[repr(u8)]
#[derive(PartialEq)]
pub enum TlsHandshakeType {
    HelloRequest       = 0,
	ClientHello        = 1,
	ServerHello        = 2,
	NewSessionTicket   = 4,
	Certificate        = 11,
	ServerKeyExchange  = 12,
	CertificateRequest = 13,
	ServerHelloDone    = 14,
	CertificateVerify  = 15,
	ClientKeyExchange  = 16,
	Finished           = 20,
	CertificateStatus  = 22,
	NextProtocol       = 67, // Not IANA assigned
}
}


enum_from_primitive! {
#[repr(u16)]
#[derive(Debug, PartialEq)]
pub enum TlsExtension {
	ServerName                       = 0,
	StatusRequest                    = 5,
	SupportedCurves                  = 10,
	SupportedPoints                  = 11,
	SignatureAlgorithms              = 13,
	ALPN                             = 16,
	SCT                              = 18, // https://tools.ietf.org/html/rfc6962#section-6
	Padding                          = 21,
	ExtendedMasterSecret             = 23, // https://tools.ietf.org/html/rfc7627
	SessionTicket                    = 35,
	NextProtoNeg                     = 13172, // not IANA assigned
	RenegotiationInfo                = 0xff01,
	ChannelID                        = 30032, // not IANA assigned

    KeyShare                         = 0x0033,
    PskKeyExchangeModes              = 0x002D,
    SupportedVersions                = 0x002B,
    CertificateCompressionAlgorithms = 0x001B,
    TokenBinding                     = 0x0018,
    EarlyData                        = 0x002A,
    PreSharedKey                     = 0x0029,
    RecordSizeLimit                  = 0x001C,
}
}

enum_from_primitive! {
#[repr(i16)]
#[derive(Debug, Hash, PartialEq, Clone, Copy)]
pub enum TlsVersion {
    // TODO
    NONE  = 0x0000,
	SSL30 = 0x0300,
	TLS10 = 0x0301,
	TLS11 = 0x0302,
	TLS12 = 0x0303,
}
}

impl Default for TlsVersion{
    fn default() -> TlsVersion {
        TlsVersion::NONE
    }
}

#[derive(Debug, PartialEq)]
pub struct ClientHelloFingerprint {
    pub record_tls_version: TlsVersion,
    pub ch_tls_version: TlsVersion,
    pub client_random: Vec<u8>,
    pub cipher_suites: Vec<u8>,
    pub compression_methods: Vec<u8>,

    pub extensions: Vec<u8>,
    pub named_groups: Vec<u8>,
    pub ec_point_fmt: Vec<u8>,
    pub sig_algs: Vec<u8>,
    pub alpn: Vec<u8>,

    // fields below are not part of final fingerprint
    pub sni: Vec<u8>,
    pub ticket_size: Option<i16>,

    pub key_share: Vec<u8>, // format [[u16, u16], [u16, u16], ...], where each element is [group, length]
    pub psk_key_exchange_modes: Vec<u8>,
    pub supported_versions: Vec<u8>,
    pub cert_compression_algs: Vec<u8>,
    pub record_size_limit : Vec<u8>,
}

pub type ClientHelloParseResult = Result<ClientHelloFingerprint, ParseError>;

impl ClientHelloFingerprint {
    pub fn from_try(a: &[u8]) -> ClientHelloParseResult {
        if a.len() < 42 {
            return Err(ParseError::ShortBuffer);
        }

        let record_type = a[0];
        if TlsRecordType::from_u8(record_type) != Some(TlsRecordType::Handshake) {
            return Err(ParseError::NotAHandshake);
        }

        let record_tls_version = match TlsVersion::from_u16(u8_to_u16_be(a[1], a[2])) {
            Some(tls_version) => tls_version,
            None => return Err(ParseError::UnknownRecordTLSVersion),
        };

        let record_length = u8_to_u16_be(a[3], a[4]);
        if usize::from_u16(record_length).unwrap() > a.len() - 5 {
            return Err(ParseError::ShortOuterRecord);
        }

        if TlsHandshakeType::from_u8(a[5]) != Some(TlsHandshakeType::ClientHello) {
            return Err(ParseError::NotAClientHello);
        }

        let ch_length = u8_to_u32_be(0, a[6], a[7], a[8]);
        if ch_length != record_length as u32 - 4 {
            return Err(ParseError::InnerOuterRecordLenContradict);
        }

        let ch_tls_version = match TlsVersion::from_u16(u8_to_u16_be(a[9], a[10])) {
            Some(tls_version) => tls_version,
            None => return Err(ParseError::UnknownChTLSVersion),
        };

        // 32 bytes of client random

        let mut offset: usize = 11;
        let c_random = ungrease_u8(&a[offset..offset+32]);
        offset += 32;

        let session_id_len = a[offset] as usize;
        offset += session_id_len + 1;
        if offset + 2 > a.len() {
            return Err(ParseError::SessionIDLenExceedBuf);
        }

        let cipher_suites_len = u8_to_u16_be(a[offset], a[offset + 1]) as usize;
        offset += 2;
        if offset + cipher_suites_len + 1 > a.len() || cipher_suites_len % 2 == 1 {
            return Err(ParseError::CiphersuiteLenMisparse);
        }

        let cipher_suites = ungrease_u8(&a[offset..offset + cipher_suites_len]);
        offset += cipher_suites_len;

        let compression_len = a[offset] as usize;
        offset += 1;
        if offset + compression_len + 2 > a.len() {
            return Err(ParseError::CompressionLenExceedBuf);
        }

        let compression_methods = a[offset..offset + compression_len].to_vec();
        offset += compression_len;

        let extensions_len = u8_to_u16_be(a[offset], a[offset + 1]) as usize;
        offset += 2;
        if offset + extensions_len > a.len() {
            return Err(ParseError::ExtensionsLenExceedBuf);
        }

        let mut ch = ClientHelloFingerprint {
            record_tls_version: record_tls_version,
            ch_tls_version: ch_tls_version,
            client_random: c_random,
            cipher_suites: cipher_suites,
            compression_methods: compression_methods,
            extensions: Vec::new(),
            named_groups: Vec::new(),
            ec_point_fmt: Vec::new(),
            sig_algs: Vec::new(),
            alpn: Vec::new(),
            sni: Vec::new(),
            ticket_size: None,
            key_share: Vec::new(),
            psk_key_exchange_modes: Vec::new(),
            supported_versions: Vec::new(),
            cert_compression_algs: Vec::new(),
            record_size_limit: Vec::new(),
        };

        let ch_end = offset + extensions_len;
        while offset < ch_end {
            if offset > ch_end - 4 {
                return Err(ParseError::ShortExtensionHeader);
            }
            let ext_len = u8_to_u16_be(a[offset + 2], a[offset + 3]) as usize;
            if offset + ext_len > ch_end {
                return Err(ParseError::ExtensionLenExceedBuf);
            }
            ch.process_extension(&a[offset..offset + 2], &a[offset + 4..offset + 4 + ext_len])?;
            offset = match (offset + 4).checked_add(ext_len) {
                Some(i) => i,
                None => return Err(ParseError::ExtensionLenExceedBuf),
            };
        }
        Ok(ch)
    }

    fn process_extension(&mut self, ext_id_u8: &[u8], ext_data: &[u8]) -> Result<(), ParseError> {
        let ext_id = u8_to_u16_be(ext_id_u8[0], ext_id_u8[1]);
        match TlsExtension::from_u16(ext_id) {
            // we copy whole ext_data, including all the redundant lengths
            Some(TlsExtension::SupportedCurves) => {
                self.named_groups = ungrease_u8(ext_data);
            }
            Some(TlsExtension::SupportedPoints) => {
                self.ec_point_fmt = ext_data.to_vec();
            }
            Some(TlsExtension::SignatureAlgorithms) => {
                self.sig_algs = ext_data.to_vec();
            }
            Some(TlsExtension::ServerName) => {
                self.sni = ext_data.to_vec();
            }
            Some(TlsExtension::SessionTicket) => {
                if ext_data.len() <= i16::max_value() as usize {
                    self.ticket_size = Some(ext_data.len() as i16)
                }
            }
            Some(TlsExtension::ALPN) => {
                /* TODO Could be greasy
   ALPN identifiers beginning with
   the prefix "ignore/".  This corresponds to the seven-octet prefix:
   0x69, 0x67, 0x6e, 0x6f, 0x72, 0x65, 0x2f.
                */
                self.alpn = ext_data.to_vec();
            }
            Some(TlsExtension::KeyShare) => {
                // key share goes [[group, size, key_itself], [group, size, key_itself], ...]
                // we want [[group, size], [group, size], ...]
                let key_share_data = ext_data.to_vec();
                if key_share_data.len() < 2 {
                    return Err(ParseError::KeyShareExtShort);
                }
                let key_share_inner_len = u8_to_u16_be(key_share_data[0], key_share_data[1]) as usize;
                let key_share_inner_data = match key_share_data.get(2 .. key_share_data.len()) {
                    Some(data) => data,
                    None => return Err(ParseError::KeyShareExtShort),
                };
                if key_share_inner_len != key_share_inner_data.len() {
                    return Err(ParseError::KeyShareExtLenMisparse);
                }
                self.key_share = parse_key_share(key_share_inner_data)?;
            }
            Some(TlsExtension::PskKeyExchangeModes) => {
                if ext_data.len() < 1 {
                    return Err(ParseError::PskKeyExchangeModesExtShort);
                }
                let psk_modes_inner_len = ext_data[0] as usize;
                if psk_modes_inner_len != ext_data.len() - 1 {
                    return Err(ParseError::PskKeyExchangeModesExtLenMisparse);
                }

                self.psk_key_exchange_modes = ungrease_u8(&ext_data[1 .. ]);
            }
            Some(TlsExtension::SupportedVersions) => {
                if ext_data.len() < 1 {
                    return Err(ParseError::SupportedVersionsExtLenMisparse);
                }
                let versions_inner_len = ext_data[0] as usize;
                if versions_inner_len != ext_data.len() - 1 {
                    return Err(ParseError::PskKeyExchangeModesExtLenMisparse);
                }

                self.supported_versions = ungrease_u8(&ext_data[1 .. ]);
            }
            Some(TlsExtension::CertificateCompressionAlgorithms) => {
                self.cert_compression_algs = ext_data.to_vec();
            }
            Some(TlsExtension::RecordSizeLimit) => {
                self.record_size_limit = ext_data.to_vec();
            }
            _ => {}
        };

        self.extensions.append(&mut ungrease_u8(ext_id_u8));
        Ok(())
    }

    pub fn get_fingerprint(&self) -> u64 {
        //let mut s = DefaultHasher::new(); // This is SipHasher13, nobody uses this...
        //let mut s = SipHasher24::new_with_keys(0, 0);
        // Fuck Rust's deprecated "holier than thou" bullshit attitude
        // We'll use SHA1 instead...

        let mut hasher = Sha1::new();
        let versions = (self.record_tls_version as u32) << 16 | (self.ch_tls_version as u32);
        hash_u32(&mut hasher, versions);


        hash_u32(&mut hasher, self.cipher_suites.len() as u32);
        hasher.input(&self.cipher_suites);

        hash_u32(&mut hasher, self.compression_methods.len() as u32);
        hasher.input(&self.compression_methods);

        hash_u32(&mut hasher, self.extensions.len() as u32);
        hasher.input(&self.extensions);

        hash_u32(&mut hasher, self.named_groups.len() as u32);
        hasher.input(&self.named_groups);

        hash_u32(&mut hasher, self.ec_point_fmt.len() as u32);
        hasher.input(&self.ec_point_fmt);

        hash_u32(&mut hasher, self.sig_algs.len() as u32);
        hasher.input(&self.sig_algs);

        hash_u32(&mut hasher, self.alpn.len() as u32);
        hasher.input(&self.alpn);

        hash_u32(&mut hasher, self.key_share.len() as u32);
        hasher.input(&self.key_share);

        hash_u32(&mut hasher, self.psk_key_exchange_modes.len() as u32);
        hasher.input(&self.psk_key_exchange_modes);

        hash_u32(&mut hasher, self.supported_versions.len() as u32);
        hasher.input(&self.supported_versions);

        hash_u32(&mut hasher, self.cert_compression_algs.len() as u32);
        hasher.input(&self.cert_compression_algs);

        hash_u32(&mut hasher, self.record_size_limit.len() as u32);
        hasher.input(&self.record_size_limit);

        let mut result = [0; 20];
        hasher.result(&mut result);
        BigEndian::read_u64(&result[0..8])
    }
}

impl fmt::Display for ClientHelloFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "record: {:?} ch: {:?} random: {:02x?} ciphers: {:X} compression: {:X} \
        extensions: {:X} curves: {:X} ec_fmt: {:X} sig_algs: {:X} alpn: {:X} sni: {}",
               self.record_tls_version, self.ch_tls_version, self.client_random.as_slice(),
               vec_u8_to_vec_u16_be(&self.cipher_suites).as_slice().as_hex(),
               &self.compression_methods.as_slice().as_hex(),
               vec_u8_to_vec_u16_be(&self.extensions).as_slice().as_hex(),
               vec_u8_to_vec_u16_be(&self.named_groups).as_slice().as_hex(),
               self.ec_point_fmt.as_slice().as_hex(),
               vec_u8_to_vec_u16_be(&self.sig_algs).as_slice().as_hex(),
               self.alpn.as_slice().as_hex(),
               String::from_utf8_lossy(self.sni.clone().as_slice()),
        )
    }
}

// Coverts array of [u8] into Vec<u8>, and performs ungrease.
// Ungrease stores all greasy extensions/ciphers/etc under single id to produce single fingerprint
// https://tools.ietf.org/html/draft-davidben-tls-grease-01
fn ungrease_u8(arr: &[u8]) -> Vec<u8> {
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
fn parse_key_share(arr: &[u8]) -> Result<Vec<u8>, ParseError> {
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

pub trait ServerHelloAccessors {
    fn set_record_tls_version(&mut self, TlsVersion);
    fn get_record_tls_version(&self) -> Option<TlsVersion>;

    fn set_sh_tls_version(&mut self, TlsVersion);
    fn get_sh_tls_version(&self) -> Option<TlsVersion>;

    fn set_server_random(&mut self, Vec<u8>);
    fn get_server_random(&self) -> Option<&Vec<u8>>;

    fn set_cipher_suite(&mut self, u16);
    fn get_cipher_suite(&self) -> Option<u16>;

    fn set_compression_method(&mut self, u8);
    fn get_compression_method(&self) -> Option<u8>;

    fn set_extensions(&mut self, Vec<u8>);
    fn get_extensions(&self) -> Option<&Vec<u8>>;
    fn append_extensions(&mut self, &mut Vec<u8>);

    fn set_elliptic_curves(&mut self, Vec<u8>);
    fn get_elliptic_curves(&self) -> Option<&Vec<u8>>;

    fn set_ec_point_fmt(&mut self, Vec<u8>);
    fn get_ec_point_fmt(&self) -> Option<&Vec<u8>>;

    fn set_alpn(&mut self, Vec<u8>);
    fn get_alpn(&self) -> Option<&Vec<u8>>;
}

#[derive(Debug, PartialEq, Default)]
pub struct ServerHelloFingerprint {
    pub record_tls_version: TlsVersion,
    pub sh_tls_version: TlsVersion,
    pub server_random: Vec<u8>,
    pub cipher_suite: u16,
    pub compression_method: u8,

    pub extensions: Vec<u8>,
    pub elliptic_curves: Vec<u8>,
    pub ec_point_fmt: Vec<u8>,
    pub alpn: Vec<u8>,
}

impl ServerHelloFingerprint {
    // NOT UNGREASED
    fn process_extension(&mut self, ext_id_u8: &[u8], ext_data: &[u8]) {
        let ext_id = u8_to_u16_be(ext_id_u8[0], ext_id_u8[1]);
        match TlsExtension::from_u16(ext_id) {
            // we copy whole ext_data, including all the redundant lengths
            Some(TlsExtension::SupportedCurves) => {
                self.set_elliptic_curves( ext_data.to_vec());
            }
            Some(TlsExtension::SupportedPoints) => {
                self.set_ec_point_fmt(ext_data.to_vec());
            }
            Some(TlsExtension::ALPN) => {
                self.set_alpn(ext_data.to_vec());
            }
            _ => {}
        };

        self.append_extensions(&mut ungrease_u8(ext_id_u8));
    }

    pub fn get_fingerprint(&self) -> u64 {
        let mut hasher = Sha1::new();

        let versions = (self.get_record_tls_version().unwrap_or_else(|| TlsVersion::NONE) as u32) << 16 | (self.get_sh_tls_version().unwrap_or_else(|| TlsVersion::NONE) as u32);
        hash_u32(&mut hasher, versions);

        let suite_and_compr = (self.get_cipher_suite().unwrap_or_else(|| 0) as u32) << 16 | (self.get_compression_method().unwrap_or_else(|| 0) as u32);
        // 8 bytes are left empty, that's fine
        hash_u32(&mut hasher, suite_and_compr as u32);

        match self.get_extensions() {
            Some(ex) => {
                hash_u32(&mut hasher, ex.len() as u32);
                hasher.input(&ex);
            }
            None => {}
        }

        match self.get_elliptic_curves() {
            Some(ec) => {
                hash_u32(&mut hasher, ec.len() as u32);
                hasher.input(&ec);
            }
            None => {}
        }

        match self.get_ec_point_fmt() {
            Some(ecpf) => {
                hash_u32(&mut hasher, ecpf.len() as u32);
                hasher.input(&ecpf);
            }
            None => {}
        }

        match self.get_alpn() {
            Some(alpn) => {
                hash_u32(&mut hasher, alpn.len() as u32);
                hasher.input(&alpn);
            }
            None => {}
        }

        let mut result = [0; 20];
        hasher.result(&mut result);
        BigEndian::read_u64(&result[0..8])
    }
}

pub struct ServerKeyExchange {
    pub server_params: Vec<u8>,
    pub signature: Option<Vec<u8>>,
}

pub struct ServerReturn {
    pub server_hello: Option<ServerHelloFingerprint>,
    pub cert: Option<openssl::x509::X509>,
    pub server_key_exchange: Option<ServerKeyExchange>,
}

impl ServerHelloAccessors for ServerHelloFingerprint { 
    fn set_record_tls_version(&mut self, t: TlsVersion) {
        self.record_tls_version = t;
    }

    fn get_record_tls_version(&self) -> Option<TlsVersion> {
        Some(self.record_tls_version)
    }

    fn set_sh_tls_version(&mut self, t: TlsVersion) {
        self.sh_tls_version = t;
    }

    fn get_sh_tls_version(&self) -> Option<TlsVersion> {
        Some(self.sh_tls_version)
    }

    fn set_server_random(&mut self, v:Vec<u8>) {
        self.server_random = v;
    }

    fn get_server_random(&self) -> Option<&Vec<u8>> {
        Some(&self.server_random)
    }

    fn set_cipher_suite(&mut self, cs: u16) {
        self.cipher_suite = cs;
    }

    fn get_cipher_suite(&self) -> Option<u16> {
        Some(self.cipher_suite)
    }

    fn set_compression_method(&mut self, cm: u8) {
        self.compression_method = cm;
    }

    fn get_compression_method(&self) -> Option<u8> {
        Some(self.compression_method)
    }

    fn set_extensions(&mut self, ex: Vec<u8>) {
        self.extensions = ex;
    }

    fn get_extensions(&self) -> Option<&Vec<u8>> {
        Some(&self.extensions)
    }

    fn append_extensions(&mut self, v: &mut Vec<u8>) {
        self.extensions.append(v);
    }

    fn set_elliptic_curves(&mut self, ec: Vec<u8>) {
        self.elliptic_curves = ec;
    }

    fn get_elliptic_curves(&self) -> Option<&Vec<u8>> {
        Some(&self.elliptic_curves)
    }

    fn set_ec_point_fmt(&mut self, ecpf: Vec<u8>) {
        self.ec_point_fmt = ecpf;
    }

    fn get_ec_point_fmt(&self) -> Option<&Vec<u8>> {
        Some(&self.ec_point_fmt)
    }

    fn set_alpn(&mut self, alpn: Vec<u8>) {
        self.alpn = alpn;
    }

    fn get_alpn(&self) -> Option<&Vec<u8>> {
        Some(&self.alpn)
    }
}

impl ServerHelloAccessors for ServerReturn {
    fn set_record_tls_version(&mut self, t: TlsVersion) {
        match self.server_hello {
            Some(ref mut sh) => {
                sh.record_tls_version = t;
            }
            _ => {}
        }
    }

    fn get_record_tls_version(&self) -> Option<TlsVersion> {
        match self.server_hello {
            Some(ref sh) => {Some(sh.record_tls_version)}
            None => {None}
        }
    }

    fn set_sh_tls_version(&mut self, t: TlsVersion) {
        match self.server_hello {
            Some(ref mut sh) => {sh.sh_tls_version = t;}
            _ => {}
        }
    }

    fn get_sh_tls_version(&self) -> Option<TlsVersion> {
        match self.server_hello {
            Some(ref sh) => {Some(sh.sh_tls_version)}
            None => {None}
        }
    }

    fn set_server_random(&mut self, v:Vec<u8>) {
        match self.server_hello {
            Some(ref mut sh) => {
                sh.server_random = v;
            }
            _ => {}
        }
    }

    fn get_server_random(&self) -> Option<&Vec<u8>> {
        match self.server_hello {
            Some(ref sh) => {Some(&sh.server_random)}
            None => {None}
        }
    }

    fn set_cipher_suite(&mut self, cs: u16) {
        match self.server_hello {
            Some(ref mut sh) => {
                sh.cipher_suite = cs;
            }
            _ => {}
        }
    }

    fn get_cipher_suite(&self) -> Option<u16> {
        match self.server_hello {
            Some(ref sh) => {Some(sh.cipher_suite)}
            None => {None}
        }
    }

    fn set_compression_method(&mut self, cm: u8) {
        match self.server_hello {
            Some(ref mut sh) => {
                sh.compression_method = cm;
            }
            _ => {}
        }
    }

    fn get_compression_method(&self) -> Option<u8> {
        match self.server_hello {
            Some(ref sh) => {Some(sh.compression_method)}
            None => {None}
        }
    }

    fn set_extensions(&mut self, ex: Vec<u8>) {
        match self.server_hello {
            Some(ref mut sh) => {
                sh.extensions = ex;
            }
            _ => {}
        }
    }

    fn get_extensions(&self) -> Option<&Vec<u8>> {
        match self.server_hello {
            Some(ref sh) => {Some(&sh.extensions)}
            None => {None}
        }
    }

    fn append_extensions(&mut self, v: &mut Vec<u8>) {
        match self.server_hello{
            Some(ref mut sh) => {
                sh.extensions.append(v);
            }
            _ => {}
        }
    }

    fn set_elliptic_curves(&mut self, ec: Vec<u8>) {
        match self.server_hello {
            Some(ref mut sh) => {
                sh.elliptic_curves = ec;
            }
            _ => {}
        }
    }

    fn get_elliptic_curves(&self) -> Option<&Vec<u8>> {
        match self.server_hello {
            Some(ref sh) => {Some(&sh.elliptic_curves)}
            None => {None}
        }
    }

    fn set_ec_point_fmt(&mut self, ecpf: Vec<u8>) {
        match self.server_hello {
            Some(ref mut sh) => {
                sh.ec_point_fmt = ecpf;
            }
            _ => {}
        }
    }

    fn get_ec_point_fmt(&self) -> Option<&Vec<u8>> {
        match self.server_hello {
            Some(ref sh) => {Some(&sh.ec_point_fmt)}
            None => {None}
        }
    }

    fn set_alpn(&mut self, alpn: Vec<u8>) {
        match self.server_hello {
            Some(ref mut sh) => {
                sh.alpn = alpn;
            }
            _ => {}
        }
    }

    fn get_alpn(&self) -> Option<&Vec<u8>> {
        match self.server_hello {
            Some(ref sh) => {Some(&sh.alpn)}
            None => {None}
        }
    }
}

pub type ServerParseResult = Result<ServerReturn, ParseError>;
pub type ServerHelloParseResult = Result<ServerHelloFingerprint, ParseError>;
pub type ServerCertificateParseResult = Result<X509, ParseError>;

impl ServerReturn {
    pub fn get_server_hello(&self) -> Option<&ServerHelloFingerprint> {
        match self.server_hello {
            Some(ref sh) => {Some(&sh)}
            None => {None}
        }
    }

    pub fn get_certificate(&self) -> Option<&openssl::x509::X509> {
        match self.cert {
            Some(ref cert) => {Some(&cert)}
            None => {None}
        }
    }

    pub fn get_server_key_exchange(&self) -> Option<&ServerKeyExchange> {
        match self.server_key_exchange {
            Some(ref ske) => {Some(&ske)}
            None => {None}
        }
    }

    pub fn find_server_hello(a: &[u8], ft: &mut FlowTracker) -> ServerHelloParseResult {
        let of = ft.overflow;
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

        let cipher_suite = u8_to_u16_be(a[offset], a[offset + 1]);
        offset += 2;

        let compression_method = a[offset];
        offset += 1;


        let mut sh = ServerHelloFingerprint {
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

        ft.overflow = of+offset;

        Ok(sh)
    }

    pub fn find_certificate(a: &[u8], ft: &mut FlowTracker) -> ServerCertificateParseResult {
        let of = ft.overflow;
        if a.len() < of {
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
            // have an overflow of certs between packets
            ft.overflow = record_length as usize - a[of..a.len()].len();
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
            Ok(cert) => {
                return Ok(cert);
            }
            Err(_) => {
                return Err(ParseError::NotACertificate);
            }
        }
    }

    pub fn from_try(a: &[u8], ft: &mut FlowTracker) -> ServerParseResult {
        // not as important for general check.

        let mut sr = ServerReturn {
            server_hello: None,
            cert: None,
            server_key_exchange: None,
        };

        // first check for a ServerHello:
        match ServerReturn::find_server_hello(a, ft) {
            Ok(sh) => {
                sr.server_hello = enum_primitive::Option::Some(sh);
            }
            Err(_) => {} // didn't find server hello
        }
        
        // now check for other records!

        match ServerReturn::find_certificate(a, ft) {
            Ok(cert) => {
                sr.cert = enum_primitive::Option::Some(cert);
            }
            Err(_) => {} // didn't find a certificate
        }

        Ok(sr)
    }


}

impl fmt::Display for ServerHelloFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "record: {:?} sh: {:?} random: {:02x?} cipher: {:X} compression: {:X} \
        extensions: {:X} curves: {:X} ec_fmt: {:X} alpn: {:X}",
               self.record_tls_version, self.sh_tls_version, self.server_random.as_slice(),
               &self.cipher_suite,
               &self.compression_method,
               vec_u8_to_vec_u16_be(&self.extensions).as_slice().as_hex(),
               vec_u8_to_vec_u16_be(&self.elliptic_curves).as_slice().as_hex(),
               self.ec_point_fmt.as_slice().as_hex(),
               self.alpn.as_slice().as_hex(),
        )
    }
}

impl fmt::Display for ServerReturn {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.get_server_hello() {
            Some(ref sh) => {write!(f, "{}", sh)}
            None => {write!(f, "No server Hello")}
        }
    }
}

#[cfg(test)]
mod tests {
    use tls_parser::{ClientHelloFingerprint, TlsVersion};

    fn from_hex(hex: &str) -> Vec<u8>
    {
        let mut out = Vec::new();
        for i in (0..hex.len() / 2).map(|x| x * 2) {
            out.push(u8::from_str_radix(&hex[i..i + 2], 16).unwrap());
        }
        out
    }


    #[test]
    fn test_empty_fingerprint() {
        let ch = ClientHelloFingerprint {
            record_tls_version: TlsVersion::TLS10,
            ch_tls_version: TlsVersion::TLS12,
            cipher_suites: Vec::new(),
            compression_methods: Vec::new(),
            extensions: Vec::new(),
            named_groups: Vec::new(),
            ec_point_fmt: Vec::new(),
            sig_algs: Vec::new(),
            alpn: Vec::new(),
            sni: Vec::new(),
            ticket_size: None,
            key_share: Vec::new(),
            psk_key_exchange_modes: Vec::new(),
            supported_versions: Vec::new(),
            cert_compression_algs: Vec::new(),
            record_size_limit: Vec::new(),
        };
        assert_eq!(ch.get_fingerprint(), 6116981759083077708);
    }


    #[test]
    fn test_chrome_fingerprint() {
        let ch = ClientHelloFingerprint {
            record_tls_version: TlsVersion::TLS10,
            ch_tls_version: TlsVersion::TLS12,
            cipher_suites: vec![0x0a, 0x0a, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c,
                                0xc0, 0x30, 0xcc, 0xa9, 0xcc, 0xa8, 0xc0, 0x13,
                                0xc0, 0x14, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f,
                                0x00, 0x35, 0x00, 0x0a],
            compression_methods: vec![0],
            extensions: vec![0x0a, 0x0a, 0xff, 0x01, 0x00, 0x00, 0x00, 0x17,
                             0x00, 0x23, 0x00, 0x0d, 0x00, 0x05, 0x00, 0x12,
                             0x00, 0x10, 0x75, 0x50, 0x00, 0x0b, 0x00, 0x0a,
                             0x0a, 0x0a],
            named_groups: vec![0x00, 0x08, 0x0a, 0x0a, 0x00, 0x1d, 0x00, 0x17,
                               0x00, 0x18],
            ec_point_fmt: vec![0x01, 0x00],
            sig_algs: vec![0x00, 0x00, 0x00, 0x12, 0x00, 0x04, 0x00, 0x03,
                           0x00, 0x08, 0x00, 0x04, 0x00, 0x04, 0x00, 0x01,
                           0x00, 0x05, 0x00, 0x03, 0x00, 0x08, 0x00, 0x05,
                           0x00, 0x05, 0x00, 0x01, 0x00, 0x08, 0x00, 0x06,
                           0x00, 0x06, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01],
            alpn: vec![0x00, 0x00, 0x00, 0x0c, 0x00, 0x02, 0x00, 0x68,
                       0x00, 0x32, 0x00, 0x08, 0x00, 0x68, 0x00, 0x74,
                       0x00, 0x74, 0x00, 0x70, 0x00, 0x2f, 0x00, 0x31,
                       0x00, 0x2e, 0x00, 0x31],
            sni: Vec::new(),
            ticket_size: None,
            key_share: Vec::new(),
            psk_key_exchange_modes: Vec::new(),
            supported_versions: Vec::new(),
            cert_compression_algs: Vec::new(),
            record_size_limit: Vec::new(),
        };
        assert_eq!(ch.get_fingerprint(), 2850294275305369904);
    }

    #[test]
    fn test_parse_ie() {
        let correct = ClientHelloFingerprint {
            record_tls_version: TlsVersion::TLS12,
            ch_tls_version: TlsVersion::TLS12,
            cipher_suites: vec![0x00, 0x3c, 0x00, 0x2f, 0x00, 0x3d, 0x00, 0x35,
                                0x00, 0x05, 0x00, 0x0a, 0xc0, 0x27, 0xc0, 0x13,
                                0xc0, 0x14, 0xc0, 0x2b, 0xc0, 0x23, 0xc0, 0x2c,
                                0xc0, 0x24, 0xc0, 0x09, 0xc0, 0x0a, 0x00, 0x40,
                                0x00, 0x32, 0x00, 0x6a, 0x00, 0x38, 0x00, 0x13,
                                0x00, 0x04],
            compression_methods: vec![0],
            extensions: vec![0x00, 0x00, 0x00, 0x05, 0x00, 0x0a, 0x00, 0x0b,
                             0x00, 0x0d, 0x00, 0x17, 0xff, 0x01],
            named_groups: vec![0x00, 0x04, 0x00, 0x17, 0x00, 0x18],
            ec_point_fmt: vec![0x01, 0x00],
            sig_algs: vec![0x00, 0x0e, 0x04, 0x01, 0x05, 0x01, 0x02, 0x01,
                           0x04, 0x03, 0x05, 0x03, 0x02, 0x03, 0x02, 0x02],
            alpn: vec![],
            sni: Vec::new(),
            ticket_size: None,
            key_share: Vec::new(),
            psk_key_exchange_modes: Vec::new(),
            supported_versions: Vec::new(),
            cert_compression_algs: Vec::new(),
            record_size_limit: Vec::new(),
        };

        let buf = from_hex("16030300b8010000b4030359dd0e129dddd32e1645a018f43d7685f27972f4f518f5092d5105377b1448c200002a003c002f003d00350005000ac027c013c014c02bc023c02cc024c009c00a00400032006a00380013000401000061000000270025000022696531315f3077696e646f7773372e66696e6765727072696e742e637266732e696f000500050100000000000a0006000400170018000b00020100000d0010000e040105010201040305030203020200170000ff01000100");

        let res = ClientHelloFingerprint::from_try(&buf);

        assert_eq!(res, Ok(correct));
    }

    #[test]
    fn test_parse_chrome() {
        let correct = ClientHelloFingerprint {
            record_tls_version: TlsVersion::TLS10,
            ch_tls_version: TlsVersion::TLS12,
            cipher_suites: vec![0x0a, 0x0a, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c,
                                0xc0, 0x30, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0x14,
                                0xcc, 0x13, 0xc0, 0x13, 0xc0, 0x14, 0x00, 0x9c,
                                0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35, 0x00, 0x0a],
            compression_methods: vec![0],
            extensions: vec![0x0a, 0x0a, 0xff, 0x01, 0x00, 0x00, 0x00, 0x17,
                             0x00, 0x23, 0x00, 0x0d, 0x00, 0x05, 0x00, 0x12,
                             0x00, 0x10, 0x75, 0x50, 0x00, 0x0b, 0x00, 0x0a,
                             0x0a, 0x0a],
            named_groups: vec![0x00, 0x08, 0x0a, 0x0a, 0x00, 0x1d, 0x00, 0x17,
                               0x00, 0x18],
            ec_point_fmt: vec![0x01, 0x00],
            sig_algs: vec![0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01,
                           0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06,
                           0x06, 0x01, 0x02, 0x01],
            alpn: vec![0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74,
                       0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31],
            sni: Vec::new(),
            ticket_size: None,
            key_share: Vec::new(),
            psk_key_exchange_modes: Vec::new(),
            supported_versions: Vec::new(),
            cert_compression_algs: Vec::new(),
            record_size_limit: Vec::new(),
        };

        let buf = from_hex("16030100e2010000de03036060d2755be23452624da20b1243313e638a444f15ee3968c6a20d05b63eaeab0000206a6ac02bc02fc02cc030cca9cca8cc14cc13c013c014009c009d002f0035000a01000095dada0000ff010001000000002c002a0000276368726f6d6535365f306f73787369657272612e66696e6765727072696e742e637266732e696f0017000000230000000d00140012040308040401050308050501080606010201000500050100000000001200000010000e000c02683208687474702f312e3175500000000b00020100000a000a00086a6a001d001700187a7a000100");

        let res = ClientHelloFingerprint::from_try(&buf);
        assert_eq!(res, Ok(correct));
    }
}
