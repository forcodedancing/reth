use alloy_rlp::Decodable;
use byteorder::{LittleEndian, ReadBytesExt};
use reth_primitives::BlobSidecar;
use snap::{read::FrameDecoder, write::FrameEncoder};
use std::io::{BufWriter, Read, Result, Write};

fn snappy_write<W: Write>(w: W, data: &[u8], prefix: &[u8]) -> Result<()> {
    // Create prefix for length of packet
    let mut length_buf = [0u8; 10];
    let vin = ((data.len() as u64).to_le_bytes(), length_buf.len()).0;

    // Create writer size
    let mut wr = BufWriter::with_capacity(10 + data.len(), w);

    // Write length of packet
    wr.write_all(prefix)?;
    wr.write_all(&length_buf[..vin])?;

    // Start using streamed snappy compression
    let mut sw = FrameEncoder::new(wr);
    sw.write_all(data)?;

    // Ensure all data is flushed
    sw.into_inner()?.flush()?;

    Ok(())
}

fn snappy_reader<R: Read>(r: &mut R) -> Result<BlobSidecar> {
    // Read variant for length of message.
    let encoded_ln = r.read_u64::<LittleEndian>()?;

    // Check if payload is too big
    if encoded_ln > 16 * 1024 * 1024 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "payload too big"));
    }

    // Create a new Snappy reader
    let mut sr = FrameDecoder::new(r);

    // Read the data
    let mut raw = vec![0u8; encoded_ln as usize];
    sr.read_exact(&mut raw)?;

    // Decode the data
    let decoded = BlobSidecar::decode(&mut raw.as_slice())?;

    Ok(decoded)
}
