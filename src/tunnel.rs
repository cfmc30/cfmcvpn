use std::net::Ipv4Addr;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct VpnPacket {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub data: Vec<u8>,
}

impl VpnPacket {
    pub fn new(src_ip: &Ipv4Addr, dst_ip: &Ipv4Addr, data: &[u8]) -> VpnPacket {
        VpnPacket {
            src_ip: src_ip.clone(),
            dst_ip: dst_ip.clone(),
            data: data.to_vec(),
        }
    }
}
