use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncWriteExt, AsyncReadExt};

/// Send a confidential transaction as JSON over TCP
pub async fn send_proof(proof_json: String, address: &str) {
    let mut stream = TcpStream::connect(address).await.expect("Failed to connect");
    stream.write_all(proof_json.as_bytes()).await.expect("Failed to send data");
}

/// Receive a confidential transaction as JSON over TCP
pub async fn receive_proof(listener: &TcpListener) -> String {
    let (mut socket, _) = listener.accept().await.expect("Failed to accept connection");
    let mut buffer = vec![0; 4096];
    let n = socket.read(&mut buffer).await.expect("Failed to read data");

    String::from_utf8_lossy(&buffer[..n]).to_string()
}
