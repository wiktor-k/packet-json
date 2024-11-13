use std::path::PathBuf;

use rstest::rstest;

fn init() {
    let _ = env_logger::builder().is_test(true).try_init();
}

#[rstest]
fn main(#[files("tests/test-cases/*-Packet.pgp")] path: PathBuf) -> testresult::TestResult {
    init();
    eprintln!("ok: {path:?}");
    let mut s = Vec::new();
    let c = std::io::Cursor::new(&mut s);
    packet_json::write_packet(std::fs::File::open(path)?, c)?;
    eprintln!("Ok: {}", String::from_utf8_lossy(&s));
    Ok(())
}
