use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use std::error::Error;

/// /// Send a confidential transaction as JSON over TCP to the specified address.
pub async fn send_proof(proof_json: String, address: &str) -> Result<(), Box<dyn Error>> {
    let mut stream = TcpStream::connect(address).await?;
    println!("Connected to {}", address);
    stream.write_all(proof_json.as_bytes()).await?;
    println!("Proof sent successfully!");
    Ok(())
}

/// Receive a confidential transaction as a JSON string over TCP.
/// 
/// This fn handles partial reads by reading in a loop until the connection is closed
/// or a read returns fewer bytes than the buffer size.
pub async fn receive_proof(listener: &TcpListener) -> Result<String, Box<dyn Error>> {
    let (mut socket, addr) = listener.accept().await?;
    println!("Connection accepted from {:?}", addr);

    let mut buffer = vec![0u8; 4096];
    let mut data = Vec::new();
    loop {
        let n = socket.read(&mut buffer).await?;
        if n == 0 {
            // Connection closed.
            break;
        }
        data.extend_from_slice(&buffer[..n]);
        // If less than buffer size is read, we assume end of message.
        if n < buffer.len() {
            break;
        }
    }

    let received_data = String::from_utf8(data)?;
    println!("Received proof ({} bytes)", received_data.len());
    Ok(received_data)
}
