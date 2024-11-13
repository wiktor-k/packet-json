use std::path::PathBuf;

use rstest::rstest;

#[rstest]
fn main(#[files("tests/test-cases/*-Packet")] path: PathBuf) -> testresult::TestResult {
    eprintln!("ok: {path:?}");
    let mut s = Vec::new();
    let c = std::io::Cursor::new(&mut s);
    packet_json::write_packet(std::fs::File::open(path)?, c)?;
    eprintln!("Ok: {}", String::from_utf8_lossy(&s));
    Ok(())
}
