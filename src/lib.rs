use std::io::{Read, Write};

use pgp::packet::{Packet, PacketParser};

#[derive(Debug, serde::Serialize)]
enum Subpacket {}

#[derive(Debug, serde::Serialize)]
enum JsonPacket {
    Signature {
        version: u8,
        r#type: u8,
        pk_algo: u8,
        hash_algo: u8,
        hashed_subpackets: Vec<Subpacket>,
        unhashed_subpackest: Vec<Subpacket>,
        digest_prefix: [u8; 2],
        signature: Vec<u8>,
    },
}

fn packet_to_repr(packet: Result<Packet, pgp::errors::Error>) -> JsonPacket {
    match packet.unwrap() {
        Packet::Signature(sig) => JsonPacket::Signature {
            version: sig.config.version().into(),
            r#type: sig.config.typ.into(),
            pk_algo: sig.config.pub_alg.into(),
            hash_algo: sig.config.hash_alg.into(),
            hashed_subpackets: vec![],
            unhashed_subpackest: vec![],
            digest_prefix: sig.signed_hash_value,
            signature: vec![],
        },
        _ => todo!(),
    }
}

pub fn write_packet(source: impl Read, out: impl Write) -> testresult::TestResult {
    let pp = PacketParser::new(source);
    let converted = pp.map(packet_to_repr).collect::<Vec<_>>();
    serde_json::to_writer(out, &converted)?;
    Ok(())
}
