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
	
	modify_field(ethernet.srcAddr, meta.dmac);
	modify_field(ethernet.dstAddr, meta.smac);
	modify_field(ipv4.srcAddr, meta.dip);
	modify_field(ipv4.dstAddr, meta.sip);
    //modify_field(tcp.data1, data);

	register_read(tcp.data1, state, 0);

	add_to_field(tcp.data1, 1);
	
	
	register_write(state, 0, tcp.data1);


	modify_field(tcp.data2, 0x11111111);
	modify_field(tcp.data3, 0x2222222222222222);
	modify_field(tcp.data4, 0x3333333333333333);
	modify_field(tcp.data5, 0x4444444444444444);




	truncate(95);
}


table send_frame {
    reads {
        standard_metadata.egress_port: exact;
    }
    actions {
		rewrite_mac;
        _drop;
    }
    size: 256;
}

control ingress {
    apply(ipv4_lpm);
    apply(forward);
}

control egress {
    apply(send_frame);
}


