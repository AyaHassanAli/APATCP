

#ifndef HEADERS_P4
#define HEADERS_P4

// Ethernet header
header ethernet_t {
    mac_addr dstAddr;
    mac_addr srcAddr;
    bit<16>  etherType;
}

// IPv4 header
header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    bit<32>   srcAddr;
    bit<32>   dstAddr;
}

// TCP header
header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

// Define custom metadata if needed
struct metadata_t {
    /* Add custom metadata if required */
}

// Standard switch metadata
struct standard_metadata_t {
    bit<9>     ingress_port;
    bit<9>     egress_spec;
    bit<9>     egress_port;
    bit<32>    instance_type;
    bit<1>     drop;
    bit<16>    recirculate_port;
    bit<32>    packet_length;
    bit<32>    enq_timestamp;
    bit<19>    enq_qdepth;
    bit<32>    deq_timedelta;
    bit<19>    deq_qdepth;
    bit<48>    ingress_global_timestamp;
    bit<48>    egress_global_timestamp;
    bit<32>    mcast_grp;
    bit<16>    egress_rid;
    bit<1>     checksum_error;
    bit<3>     parser_error;
    bit<1>     priority;
}

// Parsed header stack
struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
}

#endif
