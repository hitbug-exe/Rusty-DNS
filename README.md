# Rusty DNS

The Rusty DNS Server is a robust DNS server built in Rust that offers a range of useful tools and services that can be easily accessed through the command line. In addition to serving DNS requests, this server can assist with finding client IP addresses, keeping track of the number of requests processed, rolling dice, flipping coins, converting epoch/unix timestamps to human-readable form, and providing usable IP ranges for a given IP address prefix.

# Features [Currently Implemented]

-DNS server that responds to standard DNS queries

-Finds the client IP address for incoming requests

-Counts the number of requests processed

-Rolls a die (1-6)

-Tosses a coin (heads or tails)

-Converts epoch/unix timestamps to human-readable form

-Provides usable IP ranges for a given IP address prefix

# Installation

1. Clone this repository to your local machine.
2. Navigate to the root directory of the project.
3. Run cargo build to build the project.
4. Run cargo run to start the server.

# Usage

Once the server is running, you can use any standard DNS query tool to query the server for DNS requests. The server will respond with standard DNS responses for any queries it is able to handle.

To access the handy utilities, you can use the following special domain names:

-myip.mentisnovae.tech: Returns the client IP address

-counter.mentisnovae.tech: Returns the number of requests processed

-dice.mentisnovae.tech: Rolls a die and returns a number between 1-6

-coin.mentisnovae.tech: Tosses a coin and returns either "heads" or "tails"

-time.<epoch_time>.mentisnovae.tech: Converts an epoch/unix timestamp to human-readable form (e.g. time.1618757690.mentisnovae.tech would return -"2021-04-18 10:28:10 UTC")

-cidr.<ip_address>.<prefix_length>.mentisnovae.tech: Returns the usable IP range for a given IP address prefix (e.g. -cidr.192.0.2.0.24.mentisnovae.tech would return "192.0.2.1 - 192.0.2.254")

# References

https://github.com/knadh/dns.toys

https://doc.rust-lang.org/std/sync/atomic/struct.AtomicU64.html

https://docs.rs/chrono/latest/chrono/naive/struct.NaiveDateTime.html

https://docs.rs/trust-dns-server

# Known Bugs

-The IP address service is known to misbehave due to request parsing issues.

# License

Rusty DNS is released under the MIT License. Feel free to use, modify, and distribute it as you see fit.



