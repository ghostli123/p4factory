/*
Copyright 2013-present Barefoot Networks, Inc. 

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

parser start {
    return parse_ethernet;
}

#define ETHERTYPE_IPV4 0x0800
#define IPV4_TCP 0x06

header ethernet_t ethernet;

parser parse_ethernet {
    extract(ethernet);
	set_metadata(meta.smac, latest.srcAddr);
	set_metadata(meta.dmac, latest.dstAddr);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
        default: ingress;
    }
}

header ipv4_t ipv4;

field_list ipv4_checksum_list {
        ipv4.version;
        ipv4.ihl;
        ipv4.diffserv;
        ipv4.totalLen;
        ipv4.identification;
        ipv4.flags;
        ipv4.fragOffset;
        ipv4.ttl;
        ipv4.protocol;
        ipv4.srcAddr;
        ipv4.dstAddr;
}

header_type meta_t {
    fields {
        do_forward : 1;
        ipv4_sa : 32;
        ipv4_da : 32;
        tcp_sp : 16;
        tcp_dp : 16;
        nhop_ipv4 : 32;
        if_ipv4_addr : 32;
        if_mac_addr : 48;
        is_ext_if : 1;
        tcpLength : 16;
        if_index : 8;
		smac : 48;
		dmac : 48;
		sip : 32;
		dip : 32;

    }
}

metadata meta_t meta;

//metadata meta_t meta;

header tcp_t tcp;

parser parse_tcp {
    extract(tcp);
    set_metadata(meta.tcp_sp, latest.srcPort);
    set_metadata(meta.tcp_dp, latest.dstPort);
    return ingress;
}

/*field_list tcp_checksum_list {
        ipv4.srcAddr;
        ipv4.dstAddr;
        //8'0;
        ipv4.protocol;
        //meta.tcpLength;
        tcp.srcPort;
        tcp.dstPort;
        tcp.seqNo;
        tcp.ackNo;
        tcp.dataOffset;
        tcp.res;
        tcp.flags;
        tcp.window;
        tcp.urgentPtr;
        payload;
}

field_list_calculation tcp_checksum {
    input {
        tcp_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field tcp.checksum {
    verify tcp_checksum if(valid(tcp));
    update tcp_checksum if(valid(tcp));
}*/





field_list_calculation ipv4_checksum {
    input {
        ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field ipv4.hdrChecksum  {
    verify ipv4_checksum;
    update ipv4_checksum;
}




parser parse_ipv4 {
    extract(ipv4);
	set_metadata(meta.sip, latest.srcAddr);
	set_metadata(meta.dip, latest.dstAddr);
    return select(latest.protocol) {
        IPV4_TCP : parse_tcp;
        default: ingress;
    }
}


