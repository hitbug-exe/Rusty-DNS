use clap::Parser;
use std::net::SocketAddr;

/*
Description:
defines a struct Options that holds various options related to a DNS server. The struct has three fields: udp, tcp, and domain. The udp and tcp fields are vectors of SocketAddr structs, representing the IP addresses and port numbers on which the DNS server will listen for UDP and TCP requests. The domain field is a string that represents the domain name that the DNS server is responsible for.

Parameters:
NONE

Returns:
NONE
*/
#[derive(Parser, Clone, Debug)]
pub struct Options {
    // The UDP socket addresses on which the DNS server listens for requests
    // This field is a vector of SocketAddr structs
    // The default value is "0.0.0.0:4200" and can be overridden by setting the DNS_UDP environment variable
    #[clap(long, short, default_value = "0.0.0.0:4200", env = "DNS_UDP")]
    pub udp: Vec<SocketAddr>,

    // The TCP socket addresses on which the DNS server listens for requests
    // This field is a vector of SocketAddr structs
    // The default value is an empty vector and can be overridden by setting the DNS_TCP environment variable
    #[clap(long, short, env = "DNS_TCP")]
    pub tcp: Vec<SocketAddr>,

    // The domain name that the DNS server is responsible for
    // This field is a string
    // The default value is "mentisnovae.tech" and can be overridden by setting the DNS_DOMAIN environment variable
    #[clap(long, short, default_value = "mentisnovae.tech", env = "DNS_DOMAIN")]
    pub domain: String,
}