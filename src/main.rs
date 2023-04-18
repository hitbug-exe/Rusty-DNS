use anyhow::Result;
use clap::Parser;
use handlers::Handler;
use options::Options;
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use trust_dns_server::ServerFuture;

mod handlers;
mod options;

// This constant is used to set the timeout duration for TCP connections in the DNS server.
// If a TCP connection takes longer than 10 seconds to complete, it will be closed.
// This is a reasonable timeout value for a DNS server because DNS queries are typically small and simple, and should not take very long to complete.
// A longer timeout value could leave the server vulnerable to DOS attacks or slow down the server's response times unnecessarily.
const TCP_TIMEOUT: Duration = Duration::from_secs(10);

/*
Description:
represents the core DNS server that listens to UDP and TCP connections and responds to DNS queries. The server uses the tokio runtime to asynchronously handle incoming connections. The code initializes a tracing_subscriber for logging and reads in command-line options using the Options struct. It then creates a Handler struct from the Options and initializes a ServerFuture with it. The server registers the UDP sockets and TCP listeners from the options, and then blocks until the server is done processing incoming connections.

Parameters:
None

Returns:
Result<()>: A Result indicating whether the server completed successfully or not.
*/

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize the logging framework
    tracing_subscriber::fmt::init();

    // Parse the command-line options
    let options = Options::parse();

    // Create a handler for the DNS server based on the options
    let handler = Handler::from_options(&options);

    // Create a new DNS server
    let mut server = ServerFuture::new(handler);

    // Register UDP sockets with the server
    for udp in &options.udp {
        let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), *udp);
        let socket = UdpSocket::bind(socket_addr).await?;
        server.register_socket(socket);
    }

    // Register TCP listeners with the server
    for tcp in &options.tcp {
        let listener_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), *tcp);
        let listener = TcpListener::bind(&listener_addr).await?;
        server.register_listener(listener, TCP_TIMEOUT);
    }

    // Block until the server is done processing incoming connections
    server.block_until_done().await?;

    // The server completed successfully
    Ok(())
}