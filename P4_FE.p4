#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x0800;
const bit<8> PROTO_TCP = 6;

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

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

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
}

struct metadata {
    // Add custom metadata if needed
}

register<bit<32>>(1024) syn_counter;
register<bit<32>>(1024) ack_counter;
register<bit<32>>(256)  flag_mix_counter;

parser MyParser(packet_in pkt,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTO_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action count_syn(bit<32> idx) {
        bit<32> val;
        syn_counter.read(val, idx);
        syn_counter.write(idx, val + 1);
    }

    action count_ack(bit<32> idx) {
        bit<32> val;
        ack_counter.read(val, idx);
        ack_counter.write(idx, val + 1);
    }

    action count_flag_pattern(bit<8> pattern) {
        bit<32> val;
        flag_mix_counter.read(val, pattern);
        flag_mix_counter.write(pattern, val + 1);
    }

    apply {
        // Compute FlowID as a hash of 5-tuple
        bit<32> flow_id = (bit<32>)(hdr.ipv4.srcAddr ^ hdr.ipv4.dstAddr ^ hdr.tcp.srcPort ^ hdr.tcp.dstPort);

        // Feature: SYN counter per flow
        if ((hdr.tcp.flags & 0x02) == 0x02) {  // SYN flag
            count_syn(flow_id);
        }

        // Feature: ACK counter for incomplete sessions
        if ((hdr.tcp.flags & 0x10) == 0x10) {  // ACK flag
            count_ack(flow_id);
        }

        // Feature: TCP flag pattern tracking
        count_flag_pattern(hdr.tcp.flags);
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyDeparser(packet_out pkt, in headers hdr) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
    }
}

V1Switch(MyParser(), MyIngress(), MyEgress(), MyDeparser()) main;
