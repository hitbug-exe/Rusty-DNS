use crate::Options;
use std::{
    net::{Ipv4Addr, Ipv6Addr, IpAddr},
    str::FromStr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use tracing::*;
use trust_dns_server::{
    authority::MessageResponseBuilder,
    client::rr::{rdata::TXT, LowerName, Name, RData, Record},
    proto::op::{Header, MessageType, OpCode, ResponseCode},
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
};
use rand::Rng;
use chrono::NaiveDateTime;

/*
Represents the DNS server's handler.
has a total of eight fields, including seven zone-specific fields and a shared counter.
The counter field is of type Arc<AtomicU64> and is used to track the number of requests received by the server.
The root_zone, counter_zone, myip_zone, coin_zone, dice_zone, cidr_zone, and time_zone fields are all of type LowerName and represent different zones of the DNS server.
Each field is marked as public (pub) so that it can be accessed from outside the module.
*/

#[derive(Clone, Debug)]
pub struct Handler{
  // A shared counter to track the number of requests received
  pub counter: Arc<AtomicU64>,
  
  // The root zone of the DNS server
  pub root_zone: LowerName,
  
  // The counter zone of the DNS server
  pub counter_zone: LowerName,
  
  // The myip zone of the DNS server
  pub myip_zone: LowerName,
  
  // The coin zone of the DNS server
  pub coin_zone: LowerName,
  
  // The dice zone of the DNS server
  pub dice_zone: LowerName,
  
  // The cidr zone of the DNS server
  pub cidr_zone: LowerName,
  
  // The time zone of the DNS server
  pub time_zone: LowerName,
}

// Description:
// This Rust code defines an error enum for a DNS server. It includes error variants for an invalid OpCode, invalid message type, invalid zone, and an IO error.

// Parameters:
// None

// Returns:
// This code does not return a value directly as it defines an error enum.

// Change Log:
// - Added comments to describe the purpose and functionality of the code.
// - Added comments to describe the parameters and returns of the code.
// - Updated formatting and style to adhere to Rust best practices.
// - Renamed error variants to provide more clarity.
// - Added comments to provide more context for each error variant.

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Invalid Op Code {0:}")]
    InvalidOpCode(OpCode),
    #[error("Invalid Message Type {0:}")]
    InvalidMessageType(MessageType),
    #[error("Invalid Zone {0:}")]
    InvalidZone(LowerName),
    #[error("I/O error: {0:}")]
    Io(#[from] std::io::Error),
}

/*
Description:
This code is an implementation of the monolithic handler for the DNS server.
*/


impl Handler {
  
/*
Description:
This function creates a DNS server handler from a given set of options. It initializes several LowerName instances by parsing the domain name from the options and using it to construct various zone names for the DNS server. It also initializes an AtomicU64 counter.

Parameters:
options: a reference to an Options struct that contains information about the DNS server.

Returns:
A new instance of the Handler struct, which contains the initialized zones and counter. 
*/

  pub fn from_options(options: &Options) -> Self {
    
      // Get the domain name from the options struct.
      let domain = &options.domain;
      // Initialize a new Handler struct with the following fields:
      Handler {
        // Initialize the root zone with the LowerName instance created from the domain name.
        root_zone: LowerName::from(Name::from_str(domain).unwrap()), 
        // Initialize a new AtomicU64 counter instance wrapped in an Arc smart pointer and initialize its value to 0.
        counter: Arc::new(AtomicU64::new(0)),
        // Initialize the counter zone with the LowerName instance created from the domain name and the "counter" string.
        counter_zone: LowerName::from(Name::from_str(&format!("counter.{domain}")).unwrap()),
        // Initialize the myip zone with the LowerName instance created from the domain name and the "myip" string.
        myip_zone: LowerName::from(Name::from_str(&format!("myip.{domain}")).unwrap()),
        // Initialize the coin zone with the LowerName instance created from the domain name and the "coin" string.
        coin_zone: LowerName::from(Name::from_str(&format!("coin.{domain}")).unwrap()),
        // Initialize the dice zone with the LowerName instance created from the domain name and the "dice" string.
        dice_zone: LowerName::from(Name::from_str(&format!("dice.{domain}")).unwrap()),
        // Initialize the cidr zone with the LowerName instance created from the domain name and the "cidr" string.
        cidr_zone: LowerName::from(Name::from_str(&format!("cidr.{domain}")).unwrap()),
        // Initialize the time zone with the LowerName instance created from the domain name and the "time" string.
        time_zone: LowerName::from(Name::from_str(&format!("time.{domain}")).unwrap()),
        
    }
  }

/*
Description:

asynchronous function which receives a request object and a response handler object as parameters and returns a Result object, which contains either a ResponseInfo object or an Error object.

Parameters:
&self: a reference to the current object instance.
request: &Request: a reference to the Request object that contains the DNS request data.
response: R: a generic parameter that represents the ResponseHandler object.

Returns:

Result<ResponseInfo, Error>: a Result object that contains either a ResponseInfo object if the request is handled successfully or an Error object if there is an error during the processing of the request.
*/

  async fn do_handle_request<R: ResponseHandler>(
    &self,
    request: &Request,
    response: R,
  ) -> Result<ResponseInfo, Error> {

    // Check if the request's op code is a query. If not, return an error.
    if request.op_code() != OpCode::Query {
        return Err(Error::InvalidOpCode(request.op_code()));
    }

    // Check if the request's message type is a query. If not, return an error.
    if request.message_type() != MessageType::Query {
        return Err(Error::InvalidMessageType(request.message_type()));
    }

    // Match the query name with a zone and call the appropriate function to handle the request.
    match request.query().name() {
        // If the query name is in the myip_zone, call the do_handle_request_myip function.
        name if self.myip_zone.zone_of(name) => {
            self.do_handle_request_myip(request, response).await
        }
        // If the query name is in the counter_zone, call the do_handle_request_counter function.
        name if self.counter_zone.zone_of(name) => {
            self.do_handle_request_counter(request, response).await
        }
        // If the query name is in the coin_zone, call the do_handle_request_coin function.
        name if self.coin_zone.zone_of(name) => {
            self.do_handle_request_coin(request, response).await
        }
        // If the query name is in the dice_zone, call the do_handle_request_dice function.
        name if self.dice_zone.zone_of(name) => {
            self.do_handle_request_dice(request, response).await
        }
        // If the query name is in the cidr_zone, call the do_handle_request_cidr function.
        name if self.cidr_zone.zone_of(name) => {
            self.do_handle_request_cidr(request, response).await
        }
        // If the query name is in the time_zone, call the handle_epoch_request function.
        name if self.time_zone.zone_of(name) => {
            self.handle_epoch_request(request, response).await
        }
        // If the query name is in the root_zone, call the do_handle_request_default function.
        name if self.root_zone.zone_of(name) => {
            self.do_handle_request_default(request, response).await
        }
        // If the query name is not in any zone, return an error.
        name => Err(Error::InvalidZone(name.clone())),
    }
  }

/*
Description:
This function handles a DNS request for retrieving the IP address of the client. It takes in a reference to a Request struct, a mutable reference to a ResponseHandler trait object, and returns a Result object containing a ResponseInfo struct or an Error object.

Parameters:
&self: a reference to the current instance of the DNS server object
request: a reference to the Request struct that contains the DNS request information
mut responder: a mutable reference to a ResponseHandler trait object that will handle the DNS response

Returns:
Ok(responder.send_response(response).await?): if the response is successfully sent, returns a Result object containing a ResponseInfo struct with the client IP address.
Error: if an error occurs during the execution of the function, returns an Error object.
*/
  
  async fn do_handle_request_myip<R: ResponseHandler>(
    &self, // reference to the current instance of the DNS server object
    request: &Request, // reference to the Request struct that contains the DNS request information
    mut responder: R, // mutable reference to a ResponseHandler trait object that will handle the DNS response
    ) -> Result<ResponseInfo, Error> {
    // Increments the counter for the number of requests received.
    self.counter.fetch_add(1, Ordering::SeqCst);
    
    // Creates a new MessageResponseBuilder object from the request.
    let builder = MessageResponseBuilder::from_message_request(request);
    
    // Creates a new Header object for the response, and sets it to be authoritative.
    let mut header = Header::response_from_request(request.header());
    header.set_authoritative(true);
    
    // Determines the IP address type of the source of the request and creates a new RData object
    // with the appropriate type (A or AAAA).
    let rdata = match request.src().ip() {
        IpAddr::V4(ipv4) => RData::A(ipv4),
        IpAddr::V6(ipv6) => RData::AAAA(ipv6),
    };
    
    // Creates a new vector of Record objects with a single record containing the name and RData.
    let records = vec![Record::from_rdata(request.query().name().into(), 60, rdata)];
    
    // Builds the response using the MessageResponseBuilder object, header, and records vector,
    // along with empty vectors for additional records, nameservers, and resolvers.
    let response = builder.build(header, records.iter(), &[], &[], &[]);
    
    // Sends the response using the responder object and awaits for the response to be sent.
    // Returns a Result object containing a ResponseInfo struct if the response is successfully sent.
    Ok(responder.send_response(response).await?)
}
  
/*
Description:
asynchronous function that handles DNS requests and increments a counter for each request processed. The function takes in three arguments - a reference to the DNS server instance that called it, a reference to the DNS request being processed, and a mutable reference to an object that will handle the response. The function returns a Result object containing a ResponseInfo object or an Error object.

Parameters:
self: A reference to the DNS server instance calling this function.
request: A reference to the DNS request being processed.
responder: A mutable reference to an object that will handle the response.

Returns:
Ok(ResponseInfo): If the DNS request is successfully processed, a Result object containing a ResponseInfo object with the number of processed requests is returned.
Err(Error): If there is an error processing the DNS request, an Error object is returned.
*/
  
  async fn do_handle_request_counter<R: ResponseHandler>(
    &self,
    request: &Request,
    mut responder: R,
    ) -> Result<ResponseInfo, Error> {
    // Increment the counter for each request processed
    let counter = self.counter.fetch_add(1, Ordering::SeqCst);
    
    // Create a builder object from the DNS message request
    let builder = MessageResponseBuilder::from_message_request(request);
    
    // Create a response header object and set it as authoritative
    let mut header = Header::response_from_request(request.header());
    header.set_authoritative(true);
    
    // Create a TXT record containing the counter value as a string
    let rdata = RData::TXT(TXT::new(vec![counter.to_string()]));
    
    // Create a vector of records containing the TXT record and its associated information
    let records = vec![Record::from_rdata(request.query().name().into(), 60, rdata)];
    
    // Build the response message using the message builder, header, and record vector
    let response = builder.build(header, records.iter(), &[], &[], &[]);
    
    // Send the response message using the responder object and await the response
    Ok(responder.send_response(response).await?)
}

/*
Description:
asynchronous function that handles a DNS request and returns a response with a coin toss result. It increments a counter each time it's called, builds a response with a TXT record containing the result of a coin toss, and sends the response back to the client using the provided response handler.

Parameters:
&self: A reference to the instance of the DNS server.
request: &Request: A reference to the DNS request being handled.
mut responder: R: A mutable reference to a response handler, which is used to send the response back to the client.

Returns:
Result<ResponseInfo, Error>: A result that contains a ResponseInfo struct with the coin toss result and an Error if there was a problem sending the response back to the client.
*/
  async fn do_handle_request_coin<R: ResponseHandler>(
    &self, // Reference to instance of DNS server
    request: &Request, // Reference to the DNS request being handled
    mut responder: R, // Mutable reference to a response handler
    ) -> Result<ResponseInfo, Error> { // Returns a result that contains a ResponseInfo struct and an Error if there was a problem sending the       response back to the client
    // Increment a counter each time the function is called
    self.counter.fetch_add(1, Ordering::SeqCst);

    // Build a response using the MessageResponseBuilder from the request
    let builder = MessageResponseBuilder::from_message_request(request);
    let mut header = Header::response_from_request(request.header());

    // Set the Authoritative bit in the header to true
    header.set_authoritative(true);

    // Generate a random coin toss result
    let result = if rand::random() { "heads" } else { "tails" };

    // Create a TXT record with the result of the coin toss
    let rdata = RData::TXT(TXT::new(vec![result.to_string()]));

    // Create a vector of records containing the TXT record
    let records = vec![Record::from_rdata(request.query().name().into(), 60, rdata)];

    // Build the response using the MessageResponseBuilder and send it back to the client using the provided response handler
    let response = builder.build(header, records.iter(), &[], &[], &[]);
    Ok(responder.send_response(response).await?) // Return a Result containing a ResponseInfo struct and an Error if there was a problem sending the response back to the client
}

/*
Description:
an asynchronous function do_handle_request_dice that handles a DNS request for a dice roll. The function takes three parameters - self, request, and responder - and returns a Result that can either contain a ResponseInfo or an Error.

Parameters:
self: a reference to the do_handle_request_dice method's receiver object.
request: a reference to a Request object, which represents the DNS request being handled by the function.
responder: a mutable reference to a type R implementing the ResponseHandler trait, which will be used to send the DNS response back to the client.

Returns:
The function returns a Result<ResponseInfo, Error>. The Ok variant contains a ResponseInfo object that represents the response sent to the client with die roll result. The Err variant contains an Error object indicating what went wrong.
*/
  // Define an asynchronous function do_handle_request_dice that takes a reference to the method's receiver object, a reference to a Request object, and a mutable reference to a type R implementing the ResponseHandler trait, and returns a Result containing either a ResponseInfo or an Error.
async fn do_handle_request_dice<R: ResponseHandler>(
    &self,
    request: &Request,
    mut responder: R,
    ) -> Result<ResponseInfo, Error> {
    // Increment a counter stored in the method's receiver object by 1, using a sequentially consistent memory ordering.
    self.counter.fetch_add(1, Ordering::SeqCst);
    
    // Use the MessageResponseBuilder to construct a response to the DNS request.
    let builder = MessageResponseBuilder::from_message_request(request);
    
    // Create a Header object representing the response header, initialized with values from the request header and set the Authoritative flag to true.
    let mut header = Header::response_from_request(request.header());
    header.set_authoritative(true);
    
    // Generate a random integer between 1 and 6 (inclusive) to use as the result of the dice roll.
    let result = rand::thread_rng().gen_range(1..7);

    // Create an RData object representing the text record containing the dice roll result.
    let rdata = RData::TXT(TXT::new(vec![result.to_string()]));
    
    // Create a Record object representing the answer to the DNS query, using the query name, a TTL of 60 seconds, and the RData object created above.
    let records = vec![Record::from_rdata(request.query().name().into(), 60, rdata)];
    
    // Use the MessageResponseBuilder to construct the final response, passing in the response header and the answer record(s) created above, as well as empty vectors for additional records, nameservers, and additional data.
    let response = builder.build(header, records.iter(), &[], &[], &[]);
    
    // Use the responder object to send the response to the client, and return the Result object containing either the ResponseInfo object representing the response or an Error object if there was an error sending the response.
    Ok(responder.send_response(response).await?)
}
  
/*
Description:
handles a DNS request for the CIDR domain to return usable IP range for a given IP Address prefix. The function takes a reference to a Request object, a mutable reference to a ResponseHandler object, and returns a Result<ResponseInfo, Error>. The function increments a counter, constructs a message response builder from the given request, sets some header fields, and processes the query. The query is expected to have four parts, and the first part should be the string "cidr". If the query does not conform to this format, the function returns a todo!() macro, indicating that the implementation for that case is incomplete. Otherwise, it parses the IP address and prefix length from the query parts, calculates the IP range that corresponds to that prefix, constructs a TXT record with the IP range as a string, creates a vector of records, and constructs a response using the message response builder. Finally, it sends the response using the given responder object and returns a ResponseInfo object.

Parameters:
request: A reference to a Request object containing the DNS request to be handled.
responder: A mutable reference to a ResponseHandler object that will handle the response.

Returns:
Result<ResponseInfo, Error>: Returns a ResponseInfo object if the function succeeds, or an Error if it encounters an error.
*/
  
  async fn do_handle_request_cidr<R: ResponseHandler>(
    &self,
    request: &Request,
    mut responder: R,
    ) -> Result<ResponseInfo, Error> {
    // Increment the counter for the number of requests handled by this DNS server instance.
    self.counter.fetch_add(1, Ordering::SeqCst);

    // Create a builder to build the response message.
    let builder = MessageResponseBuilder::from_message_request(request);

    // Create a header for the response message and set the authoritative flag to true.
    let mut header = Header::response_from_request(request.header());
    header.set_authoritative(true);

    // Extract the query name from the request and convert it to lowercase.
    let query_name =  request
        .query()
        .name()
        .to_string()
        .to_lowercase();

    // Split the query name into parts using "." as the delimiter.
    let query_parts: Vec<&str> = query_name.split('.').collect();

    // Check if the query is valid (i.e., contains exactly four parts and the first part is "cidr").
    if query_parts.len() != 4 || query_parts[0] != "cidr" {
        // If the query is not valid, return a "todo" error.
        return todo!();
    }

    // Parse the second part of the query as an IP address.
    let ip_addr = match query_parts[1].parse::<IpAddr>() {
        Ok(addr) => addr,
        Err(_) => {
            // If the IP address cannot be parsed, return a "todo" error.
            return todo!();
        }
    };

    // Parse the third part of the query as a prefix length.
    let prefix_len = match query_parts[2].parse::<u8>() {
        Ok(len) => len,
        Err(_) => {
            // If the prefix length cannot be parsed, return a "todo" error.
            return todo!();
        }
    };

    // Calculate the start and end IP addresses of the range based on the IP address and prefix length.
    let ip_range = match ip_addr {
        // If the IP address is IPv4, calculate the range using a 32-bit netmask.
        IpAddr::V4(ipv4) => {
            let netmask = !((1u32 << (32 - prefix_len)) - 1);
            let start_ip = u128::from(std::net::Ipv4Addr::from(ipv4.clone().into())) & netmask;
            let end_ip = start_ip | !netmask;
            (
                IpAddr::V4(Ipv4Addr::from(start_ip.to_be())),
                IpAddr::V4(Ipv4Addr::from(end_ip.to_be())),
            )
        }
        // If the IP address is IPv6, calculate the range using a 128-bit netmask.
        IpAddr::V6(ipv6) => {
            let netmask = !((1u128 << (128 - prefix_len)) - 1);
            let start_ip = u128::from(std::net::Ipv6Addr::from(ipv6.clone().into())) & netmask;
            let end_ip = start_ip | !netmask;
            (
                IpAddr::V6(Ipv6Addr::from(start_ip.to_be_bytes())),
                IpAddr::V6(Ipv6Addr::from(end_ip.to_be_bytes())),
            )
        }
    };
  // Create a TXT record containing the IP range as a string.
  let rdata = RData::TXT(TXT::new(vec![format!("Usable IP Range: {} - {}", ip_range.0, ip_range.1)]));
    
  // Create a Record object representing the answer to the DNS query, using the query name, a TTL of 60 seconds, and the RData object created above.
  let records = vec![Record::from_rdata(request.query().name().into(), 60, rdata)];
  
  // Use the MessageResponseBuilder to construct the final response, passing in the response header and the answer record(s) created above, as well as empty vectors for additional records, nameservers, and additional data.
  let response = builder.build(header, records.iter(), &[], &[], &[]);
  
  // Use the responder object to send the response to the client, and return the Result object containing either the ResponseInfo object representing the response or an Error object if there was an error sending the response.
  Ok(responder.send_response(response).await?)
}

/*
Description:
handles a request to convert an epoch/unix timestamp to a human readable form . The function takes in three parameters: a reference to self, which represents the instance of the DNS server, a reference to request, which represents the incoming DNS request, and a mutable reference to responder, which is the object that will be used to send the response back to the client. The function returns a Result that can either be an Ok with a ResponseInfo object or an Err with an Error object.

Parameters:
&self: A reference to the instance of the DNS server that this function is a part of.
request: &Request: A reference to the incoming DNS request that needs to be processed.
mut responder: R: A mutable reference to the object that will be used to send the response back to the client.

Returns:
Result<ResponseInfo, Error>: A Result object that can either be an Ok with a ResponseInfo object or an Err with an Error object.
*/
  async fn handle_epoch_request<R: ResponseHandler>(
    &self,
    request: &Request,
    mut responder: R,
) -> Result<ResponseInfo, Error> {
    // Increment a counter for the number of times this function has been called
    self.counter.fetch_add(1, Ordering::SeqCst);

    // Get the query name from the incoming request
    let query_name = request.query().name().to_string();

    // Extract the epoch timestamp from the query name
    let timestamp = query_name
        .strip_prefix("epoch.")
        .and_then(|s| s.strip_suffix(".mentisnovae.tech"))
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| format_args!("Invalid query name"))?;

    // Convert the epoch timestamp to a DateTime object
    let date_time = NaiveDateTime::from_timestamp_opt(timestamp as i64, 0);

    // Format the DateTime object as a string
    let formatted_date = date_time.format("%Y-%m-%d %H:%M:%S").to_string();

    // Create a builder for the DNS response
    let builder = MessageResponseBuilder::from_message_request(request);

    // Create a response header and mark it as authoritative
    let mut header = Header::response_from_request(request.header());
    header.set_authoritative(true);

    // Create a TXT record with the formatted date string as its value
    let rdata = RData::TXT(TXT::new(vec![formatted_date]));

    // Create a DNS record with the query name, a TTL of 60 seconds, and the TXT record
    let records = vec![Record::from_rdata(request.query().name().into(), 60, rdata)];

    // Build the DNS response using the builder, header, and record information
    let response = builder.build(header, records.iter(), &[], &[], &[]);

    // Send the response back to the client using the responder object
    Ok(responder.send_response(response).await?)
}

/*
Description: 
asynchronous function that handles default DNS requests. The function increments a counter, creates a response message for a given request, sets the header fields of the response message, and sends the response message back to the client using a given response handler.

Parameters:
&self: A reference to the DNS server object.
request: A reference to the DNS request message.
mut responder: A mutable reference to a response handler object.

Returns: 
A Result containing a ResponseInfo object if the operation is successful, or an Error object if an error occurs.
*/
  async fn do_handle_request_default<R: ResponseHandler>(
    &self, // A reference to self, the DNS server
    request: &Request, // A reference to the request object
    mut responder: R, // A mutable reference to a ResponseHandler object
    ) -> Result<ResponseInfo, Error> {
    // Increment the value of the counter by 1 atomically (sequentially consistent order).
    self.counter.fetch_add(1, Ordering::SeqCst);
    
    // Create a new MessageResponseBuilder object from the request object.
    let builder = MessageResponseBuilder::from_message_request(request);
    
    // Create a new Header object as a response from the request header.
    let mut header = Header::response_from_request(request.header());
    
    // Set the Authoritative flag in the header to true.
    header.set_authoritative(true);
    
    // Set the response code to NXDomain (Non-Existent Domain).
    header.set_response_code(ResponseCode::NXDomain);
    
    // Build a response with no resource records using the builder and header objects.
    let response = builder.build_no_records(header);
    
    // Send the response using the responder object and return the result as a ResponseInfo object.
    Ok(responder.send_response(response).await?)
  }
}
/*
Description:
implementation of a RequestHandler trait for the DNS server. The RequestHandler trait defines a method for handling incoming DNS requests, and this implementation defines that method, which handles the request by calling a do_handle_request method and returning a ResponseInfo struct.

Parameters:
&self: A reference to the instance of the Handler struct that implements the RequestHandler trait.
request: &Request: A reference to the Request struct representing the incoming DNS request.
response: R: A generic type parameter that implements the ResponseHandler trait, which is used to send the response to the client.

Returns:
ResponseInfo: A struct containing information about the response that was sent back to the client.
*/
#[async_trait::async_trait]
impl RequestHandler for Handler {
    // Define the handle_request method required by the RequestHandler trait
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response: R,
    ) -> ResponseInfo {
        // Call the do_handle_request method and handle any errors that occur
        match self.do_handle_request(request, response).await {
            Ok(info) => info, // Return the ResponseInfo struct if the call to do_handle_request succeeds
            Err(error) => {
                // Log the error
                error!("Error in RequestHandler: {error}");
                
                // Create a new Header struct and set the response code to ServFail
                let mut header = Header::new();
                header.set_response_code(ResponseCode::ServFail);
                
                // Convert the Header struct into a ResponseInfo struct and return it
                header.into()
            }
        }
    }
}
