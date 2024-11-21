use std::io::{Read, Write};

use chrono::{DateTime, Utc};
use pgp::packet::{Packet, PacketParser, Subpacket, SubpacketData};

#[derive(Debug, serde::Serialize)]
struct JsonSubpacket {
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    critical: bool,
    id: u8,
    #[serde(flatten)]
    data: JsonSubpacketData,
}

#[derive(Debug, serde::Serialize)]
#[serde(tag = "name")]
enum JsonSubpacketData {
    IssuerFingerprint { fingerprint: Vec<u8> },
    IssuerKeyId { key_id: Vec<u8> },
    SignatureCreationTime { created_at: DateTime<Utc> },
}

#[derive(Debug, serde::Serialize)]
#[serde(tag = "name")]
enum JsonPacket {
    #[serde(rename = "SIG")]
    Signature {
        version: u8,
        r#type: u8,
        pk_algo: u8,
        hash_algo: u8,
        hashed_subpackets: Vec<JsonSubpacket>,
        unhashed_subpackets: Vec<JsonSubpacket>,
        digest_prefix: [u8; 2],
        signature: Vec<u8>,
    },
}

fn subpacket_to_repr(subpacket: &Subpacket) -> JsonSubpacket {
    let data = match &subpacket.data {
        SubpacketData::SignatureCreationTime(date_time) => {
            JsonSubpacketData::SignatureCreationTime {
                created_at: date_time.clone(),
            }
        }
        SubpacketData::SignatureExpirationTime(time_delta) => todo!(),
        SubpacketData::KeyExpirationTime(time_delta) => todo!(),
        SubpacketData::Issuer(key_id) => JsonSubpacketData::IssuerKeyId {
            key_id: key_id.as_ref().into(),
        },
        SubpacketData::PreferredSymmetricAlgorithms(small_vec) => todo!(),
        SubpacketData::PreferredHashAlgorithms(small_vec) => todo!(),
        SubpacketData::PreferredCompressionAlgorithms(small_vec) => todo!(),
        SubpacketData::KeyServerPreferences(small_vec) => todo!(),
        SubpacketData::KeyFlags(small_vec) => todo!(),
        SubpacketData::Features(small_vec) => todo!(),
        SubpacketData::RevocationReason(revocation_code, bstring) => todo!(),
        SubpacketData::IsPrimary(_) => todo!(),
        SubpacketData::Revocable(_) => todo!(),
        SubpacketData::EmbeddedSignature(signature) => todo!(),
        SubpacketData::PreferredKeyServer(_) => todo!(),
        SubpacketData::Notation(notation) => todo!(),
        SubpacketData::RevocationKey(revocation_key) => todo!(),
        SubpacketData::SignersUserID(bstring) => todo!(),
        SubpacketData::PolicyURI(_) => todo!(),
        SubpacketData::TrustSignature(_, _) => todo!(),
        SubpacketData::RegularExpression(bstring) => todo!(),
        SubpacketData::ExportableCertification(_) => todo!(),
        SubpacketData::IssuerFingerprint(fingerprint) => JsonSubpacketData::IssuerFingerprint {
            fingerprint: fingerprint.as_bytes().into(),
        },
        SubpacketData::PreferredEncryptionModes(small_vec) => todo!(),
        SubpacketData::IntendedRecipientFingerprint(fingerprint) => todo!(),
        SubpacketData::PreferredAeadAlgorithms(small_vec) => todo!(),
        SubpacketData::Experimental(_, small_vec) => todo!(),
        SubpacketData::Other(_, vec) => todo!(),
        SubpacketData::SignatureTarget(public_key_algorithm, hash_algorithm, vec) => {
            todo!()
        }
    };

    JsonSubpacket {
        critical: subpacket.is_critical,
        id: subpacket.typ().as_u8(false),
        data,
    }
}

fn packet_to_repr(packet: Result<Packet, pgp::errors::Error>) -> JsonPacket {
    match packet.unwrap() {
        Packet::Signature(sig) => JsonPacket::Signature {
            version: sig.config.version().into(),
            r#type: sig.config.typ.into(),
            pk_algo: sig.config.pub_alg.into(),
            hash_algo: sig.config.hash_alg.into(),
            hashed_subpackets: sig
                .config
                .hashed_subpackets
                .iter()
                .map(subpacket_to_repr)
                .collect(),
            unhashed_subpackets: sig
                .config
                .unhashed_subpackets
                .iter()
                .map(subpacket_to_repr)
                .collect(),
            digest_prefix: sig.signed_hash_value,
            signature: vec![],
        },
        _ => todo!(),
    }
}

pub fn write_packet(source: impl Read, out: impl Write) -> testresult::TestResult {
    let pp = PacketParser::new(source);
    let converted = pp.map(packet_to_repr).collect::<Vec<_>>();
    serde_json::to_writer_pretty(out, &converted)?;
    Ok(())
}
