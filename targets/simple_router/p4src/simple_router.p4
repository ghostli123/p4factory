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

#include "includes/headers.p4"
#include "includes/parser.p4"

action _drop() {
    drop();
}

header_type routing_metadata_t {
    fields {
        nhop_ipv4 : 32;
    }
}




metadata routing_metadata_t routing_metadata;

action set_nhop(nhop_ipv4, port) {
    modify_field(routing_metadata.nhop_ipv4, nhop_ipv4);
    modify_field(standard_metadata.egress_spec, port);
    add_to_field(ipv4.ttl, -1);
}

table ipv4_lpm {
    reads {
        ipv4.dstAddr : lpm;
    }
    actions {
        set_nhop;
        _drop;
    }
    size: 1024;
}

action set_dmac(dmac) {
    modify_field(ethernet.dstAddr, dmac);
}


table forward {
    reads {
        routing_metadata.nhop_ipv4 : exact;
    }
    actions {
        set_dmac;
        _drop;
    }
    size: 512;
}





action rewrite_mac() {
		

	//layer 2 and layer 3: switch mac and ip address
	modify_field(ethernet.srcAddr, meta.dmac);
	modify_field(ethernet.dstAddr, meta.smac);
	modify_field(ipv4.srcAddr, meta.dip);
	modify_field(ipv4.dstAddr, meta.sip);

	//layer 7: data payload
    modify_field(tcp.heartbeatResponse_start, 0xdaf400010000000d);
	
	modify_field(tcp.heartbeatResponse_middle1, 0x00000000);
	modify_field(tcp.heartbeatResponse_middle2, 0xffffffff);

	register_read(tcp.heartbeatResponse_middle2, data_index, 0);
	add_to_field(tcp.heartbeatResponse_middle2, 1);
	register_write(data_index, 0, tcp.heartbeatResponse_middle2);

	register_read(tcp.heartbeatResponse_end1, zero, 0);
	modify_field(tcp.heartbeatResponse_end1, 0x0008021001180522);
	modify_field(tcp.heartbeatResponse_end2, 0x0408011002ffffff);


	//layer 3: ip length + ip id
	subtract_from_field(ipv4.totalLen, 3); 

	register_read(ipv4.identification, ipv4_ipid, 0);
	add_to_field(ipv4.identification, 1);
	register_write(ipv4_ipid, 0, ipv4.identification);

	//layer 4
	modify_field(tcp.srcPort, meta.tcp_dp);
	modify_field(tcp.dstPort, meta.tcp_sp);

	modify_field(tcp.seqNo, meta.ackNo);
	add(tcp.ackNo, meta.seqNo, 32);

	//truncate
	truncate(95);

	//set it has been processed
	//register_write(process_done, 0, 1);
}

action copy_to_server() {
	//set it has been processed
	//register_write(process_done, 0, 0);
	//clone_i2e
}


table send_frame {
    reads {
        standard_metadata.egress_port: exact;
    }
    actions {
		rewrite_mac; copy_to_server;
        _drop;
    }
    size: 256;
}

control ingress {
    apply(ipv4_lpm);
    apply(forward);
}

control egress {
	//if (standard_metadata.instance_type == "egress clone") 
   	apply(send_frame);
}


