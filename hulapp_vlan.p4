/* -*- P4_16 -*- */
/*This is the VLAN-based HULApp code version.
  The HULApp code is based on the HULA P4_16 code 
  adopted from the P4 language tutorials (by P4 consortium) https://github.com/p4lang/tutorials which were
  conducted within SIGCOMM conference in 2017. This simplified HULA version offered in tutorials did not support flowlet logic and used the queue
  depth metric instead of link utilization (which was initially proposed by Katta et al. in the HULA paper) to track the path congestion state.

  The following logic was added to the initial simplified HULA P4_16 code in order to implement the HULApp logic:
  1. Modification of probe header fields
  2. Added link utilization metric 
  3. Added flowlet logic
  4. Added TCP parsing
  5. Added Application-Aware logic: based on the VLAN ID in the packet header, HULApp takes the packet next hop from one of the following tables:
        HULApp_nhop_QDepth (if VLAN ID equals the VLAN tag set for latency-sensitive application group)
        HULApp_nhop_pathUtil (if VLAN ID equals the VLAN tag set for less latency-sensitive application group))
*/
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_HULApp = 0x2345;
const bit<16> TYPE_VLAN = 0x8100; //VLAN is used to encapsulate traffic from latency-sensitive and less latency-sensitive applications

#define MAX_HOPS  9
#define TOR_NUM   32
#define TOR_NUM_1 33

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<21> qdepth_t; 
typedef bit<39> path_util_t; //header type in hulapp which is used for less latecy sensitive traffic metric
typedef bit<32> digest_t;
typedef bit<48> last_seen_t; //ingress flowlet timestamps in microsec
typedef bit<32> packet_length_t;
typedef bit<48> egress_global_timestamp_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header vlan_tag_t { 
	bit<3> pri;
	bit<1> cfi;
	bit<12> vid;
	bit<16> etherType;
}

header srcRoute_t {
    bit<1>    bos;
    bit<15>   port;
}

header hulapp_t {
    /* 0 is forward path, 1 is the backward path */
    bit<1>   dir;
    /* max qdepth seen so far in the forward path */
    qdepth_t qdepth;
    /* max path utilization seen so far in the forward path */
    path_util_t path_util; //metric for path utilization. 
    /* digest of the source routing list to uniquely identify each path */
    digest_t digest;
    /* flags indicating which best path at dest ToR has been changed: for latency/less-lat sensitive traffic, or for both  */
    bit<1> changed_bp_q; // 1 means that the best path based on q_depth metric has been changed at dstToR
    bit<1> changed_bp_u; // 1 means that the best path based on link_util metric has been changed at dstToR
}

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
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

header tcp_t {//
	bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
	bit<16> urgentPtr;
}

struct metadata {
    /* At destination ToR, this is the index of register 
       that saves qdepth for the best path from each source ToR */
    bit<32> index;
}

struct headers {
    ethernet_t              ethernet;
    vlan_tag_t				vlan_tag; 
    srcRoute_t[MAX_HOPS]    srcRoutes;
    ipv4_t                  ipv4;
    udp_t                   udp;
    tcp_t					tcp; 
    hulapp_t                  hulapp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_HULApp : parse_hulapp;
            TYPE_IPV4 : parse_ipv4;
            TYPE_VLAN : parse_vlan_tag; 
            default   : accept;
        }
    }

    state parse_hulapp {
        packet.extract(hdr.hulapp);
        transition parse_srcRouting;
    }

    state parse_srcRouting {
        packet.extract(hdr.srcRoutes.next);
        transition select(hdr.srcRoutes.last.bos) {
            1       : parse_ipv4;
            default : parse_srcRouting;
        }
    }

    state parse_vlan_tag { 
    	packet.extract(hdr.vlan_tag);
    	transition select(hdr.vlan_tag.etherType) {
    		TYPE_VLAN : parse_vlan_tag;
    		TYPE_IPV4 : parse_ipv4;
    		default : accept;
    	}
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            8w17: parse_udp;
            8w6 : parse_tcp; 
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }

    state parse_tcp { 
    	packet.extract(hdr.tcp);
    	transition accept; 
    }

}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    /* 
     * At destination ToR, saves the queue depth of the best path from
     * each source ToR
     */
    register<qdepth_t>(TOR_NUM) srcindex_qdepth_reg; 

    /* 
     * At destination ToR, saves the utilization metric of the best path from
     * each source ToR
     */
    register<path_util_t>(TOR_NUM) srcindex_path_util_reg; 

    /* 
     * At destination ToR, saves the digest of the best path from
     * each source ToR
     */
    register<digest_t>(TOR_NUM) srcindex_digest_reg; 

    /* At each hop, saves the next hop to reach each destination ToR (for latency-sensitive traffic) */
    register<bit<16>>(TOR_NUM) dstindex_nhop_reg_q; 

    /* At each hop, saves the next hop to reach each destination ToR (for less latency-sensitive traffic) */
    register<bit<16>>(TOR_NUM) dstindex_nhop_reg_u; 

    /* At each hop saves the next hop for each flow */
    register<bit<16>>(65536) flowlet_port_reg; 

    /*vs451: at each hop saves the timestamp when the last time flowlet was seen */
    register<last_seen_t>(65536) flowlet_last_seen_reg;

    /* This action will drop packets */
    action drop() {
        mark_to_drop();
    }

    action nop() {
    }

    action update_ttl(){
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action set_dmac(macAddr_t dstAddr){
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
    }
    
    /* This action just applies source routing */
    action srcRoute_nhop() {
        standard_metadata.egress_spec = (bit<9>)hdr.srcRoutes[0].port;
        hdr.srcRoutes.pop_front(1);
    }

    /* 
     * Runs if it is the destination ToR.
     * Control plane Gives the index of register for best path from source ToR
     */
    action hulapp_dst(bit<32> index) {
        meta.index = index;
    }

    /* 
     * In reverse path, update nexthop to a destination ToR to ingress port
     * where we receive hulapp packet
     */
    action hulapp_set_nhop_q(bit<32> index) { //vs451: set next hop for latency sensitive apps
    	dstindex_nhop_reg_q.write(index, (bit<16>)standard_metadata.ingress_port);
    }

    action hulapp_set_nhop_u(bit<32> index) { //vs451: set next hop for non-latency sensitive apps
        dstindex_nhop_reg_u.write(index, (bit<16>)standard_metadata.ingress_port); 
    }

    /* Read next hop that is saved in hulapp_set_nhop action for data packets */
    action hulapp_get_nhop_q(bit<32> index){ //vs451: read next hop for latency sensitive apps
       	bit<16> tmp;
       	dstindex_nhop_reg_q.read(tmp, index); 
       	standard_metadata.egress_spec = (bit<9>)tmp; 
  	} 

  	action hulapp_get_nhop_u(bit<32> index){ //vs451: read next hop for non latency sensitive apps
  		bit<16> tmp;
       	dstindex_nhop_reg_u.read(tmp, index); 
       	standard_metadata.egress_spec = (bit<9>)tmp;
    }

    /* Record best path at destination ToR based on queue_depth*/
    action change_best_path_at_dst_q(){
        srcindex_qdepth_reg.write(meta.index, hdr.hulapp.qdepth);
        srcindex_digest_reg.write(meta.index, hdr.hulapp.digest);
    }

    /* vs451: Record best path at destination ToR based on path_util*/
    action change_best_path_at_dst_u(){
        srcindex_path_util_reg.write(meta.index, hdr.hulapp.path_util);
        srcindex_digest_reg.write(meta.index, hdr.hulapp.digest);
    }

    /* vs451: set the hulapp changed_bp_q to 1*/
    action set_hulapp_header_bp_q(){
    	hdr.hulapp.changed_bp_q = 1;
    }

    /* vs451: set the hulapp changed_bp_u to 1*/
    action set_hulapp_header_bp_u(){
    	hdr.hulapp.changed_bp_u = 1;
    }

    /* 
     * At destination ToR, return packet to source by
     * - changing its hulapp direction
     * - send it to the port it came from
     */
    action return_hulapp_to_src(){
        hdr.hulapp.dir = 1;
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    /* 
     * In forward path:
     * - if destination ToR: run hulapp_dst to set the index based on srcAddr
     * - otherwise run srcRoute_nhop to perform source routing
     */
    table hulapp_fwd {
        key = {
            hdr.ipv4.dstAddr: exact;
            hdr.ipv4.srcAddr: exact;
        }
        actions = {
            hulapp_dst;
            srcRoute_nhop;
        }
        default_action = srcRoute_nhop;
        size = TOR_NUM_1; // TOR_NUM + 1
    }

    /* 
     * At each hop in reverse path
     * update next hop to destination ToR in registers.
     * index is set based on dstAddr
     */
    table hulapp_bwd_q { //table for updating best paths for latency sensitive applications (based on qdepth)
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            hulapp_set_nhop_q;
        }
        size = TOR_NUM;
    }

    table hulapp_bwd_u { //table for updating best paths for less latency sensitive applications (based on link util)
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            hulapp_set_nhop_u;
        }
        size = TOR_NUM;
    }

    /* 
     * in reverse path: 
     * - if source ToR (srcAddr = this switch) drop hulapp packet 
     * - otherwise, just forward in the reverse path based on source routing
     */
    table hulapp_src {
        key = {
            hdr.ipv4.srcAddr: exact;
        }
        actions = {
            drop;
            srcRoute_nhop;
        }
        default_action = srcRoute_nhop;
        size = 2;
    }

    /*
     * get nexthop based on dstAddr using registers
     */
    table hulapp_nhop_qDepth { //get next hop for latency sensitive apps
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            hulapp_get_nhop_q;
            drop;
        }
        default_action = drop;
        size = TOR_NUM;
    }

    table hulapp_nhop_pathUtil { //get next hop for non-latency sensitive apps
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            hulapp_get_nhop_u;
            drop;
        }
        default_action = drop;
        size = TOR_NUM;
    }

    /*
     * set right dmac for packets going to hosts
     */
    table dmac {
        key = {
            standard_metadata.egress_spec : exact;
        }
        actions = {
            set_dmac;
            nop;
        }
        default_action = nop;
        size = 16;
    }

    apply {
        if (hdr.hulapp.isValid()){
            if (hdr.hulapp.dir == 0){
                switch(hulapp_fwd.apply().action_run){

                    /* if hulapp_dst action ran, this is the destination ToR */
                    hulapp_dst: {

                        /* if it is the destination ToR compare qdepth */
                        qdepth_t old_qdepth;
                        srcindex_qdepth_reg.read(old_qdepth, meta.index);

                        /* if it is the destination ToR compare path_util */
                        path_util_t old_path_util; 
                        srcindex_path_util_reg.read(old_path_util, meta.index);
                        /*checking, if any of metrics has changed and updating the best path at dst ToR */
                        if ((old_qdepth > hdr.hulapp.qdepth) || (old_path_util > hdr.hulapp.path_util)){
                        	if (old_qdepth > hdr.hulapp.qdepth){
                            	change_best_path_at_dst_q();
                            	set_hulapp_header_bp_q();
                            	if (old_path_util < hdr.hulapp.path_util) {
                            		digest_t old_digest;
                            		srcindex_digest_reg.read(old_digest, meta.index);
                            		if (old_digest == hdr.hulapp.digest){
                                		srcindex_path_util_reg.write(meta.index, hdr.hulapp.path_util); //updating path_util even it has gone worse
                            		}
                            	}

                        	}

                        	if (old_path_util > hdr.hulapp.path_util){ //conditions and logic for updating path_util 
                        		change_best_path_at_dst_u();
                        		set_hulapp_header_bp_u();
                        		if (old_qdepth < hdr.hulapp.qdepth) {
                            		digest_t old_digest;
                            		srcindex_digest_reg.read(old_digest, meta.index);
                            		if (old_digest == hdr.hulapp.digest){
                                		srcindex_qdepth_reg.write(meta.index, hdr.hulapp.qdepth); //updating qdepth even it has gone worse
                            		}
                            	}

                        	}
                        	/* only return hulapp packets that update best path */
                        	return_hulapp_to_src();
                        } else{

                            /* update the best path even if it has gone worse 
                             * so that other paths can replace it later
                             */
                            digest_t old_digest;
                            srcindex_digest_reg.read(old_digest, meta.index);
                            if (old_digest == hdr.hulapp.digest){
                                srcindex_qdepth_reg.write(meta.index, hdr.hulapp.qdepth);
                                srcindex_path_util_reg.write(meta.index, hdr.hulapp.path_util); //updating the path_util as well
                            }

                            drop();
                        } 
                    }
                }
            }else {
                /* update routing table in reverse path */
                if (hdr.hulapp.changed_bp_q == 1){ //update routing table in reverse path for latency-sensitive traffic if qdepth best path changed
                	hulapp_bwd_q.apply();
            	}

            	if (hdr.hulapp.changed_bp_u == 1){ //update routing table in reverse path for non latency-sensitive traffic if link util best path changed
            		hulapp_bwd_u.apply();
            	}

                /* drop if source ToR */
                hulapp_src.apply();
            }

        }else if (hdr.vlan_tag.isValid()){//adding logic for processing flowlets from different applications (aka different vlan_ids)
        	if ((hdr.vlan_tag.vid == 12w2) || (hdr.vlan_tag.vid == 12w3)){ //check that the traffic belogs to one of applications group
        		if (hdr.ipv4.isValid()){
            		bit<16> flowlet_hash;
            		hash(
                		flowlet_hash, 
                		HashAlgorithm.crc16, 
                		16w0, 
                		{ hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.tcp.srcPort, hdr.tcp.dstPort}, 
                		32w65536);

            		/* look into hulapp tables */
            		bit<16> port;

            		bit<48> timestamp; //vs451: flowlet timestamp
            		flowlet_port_reg.read(port, (bit<32>)flowlet_hash);

            		flowlet_last_seen_reg.read(timestamp, (bit<32>)flowlet_hash);
            		bit<48> ipg = 200; 


            		if ((port == 0) || ((standard_metadata.ingress_global_timestamp - timestamp) > ipg)) {
                		/* if it is a new flow check hulapp paths */
                		if (hdr.vlan_tag.vid == 12w2){
                			hulapp_nhop_qDepth.apply(); //next hop for lat sens app
                		}
                		if (hdr.vlan_tag.vid == 12w3){
                			hulapp_nhop_pathUtil.apply(); //next hop for non lat sens app
                		}
                		flowlet_port_reg.write((bit<32>)flowlet_hash, (bit<16>)standard_metadata.egress_spec);
                		//vs451 added the following line
                		flowlet_last_seen_reg.write((bit<32>)flowlet_hash, standard_metadata.ingress_global_timestamp); //writing the time when flowlet came
            		} else{
                		/* old flowlets still use old path to avoid oscilation and packet reordering */
                		standard_metadata.egress_spec = (bit<9>)port;
                		flowlet_last_seen_reg.write((bit<32>)flowlet_hash, standard_metadata.ingress_global_timestamp); //updating the timestamp for old flowlets
            		}

            		/* set the right dmac so that ping and iperf work */
            		dmac.apply();
        		}else {
            		drop();
        		}

        		if (hdr.ipv4.isValid()){
            		update_ttl();
        		}
        	}
        }
        else {
            drop();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    /* action for timedelta estimation to the closest extent of 2 
    (as P4 target does not support division - only bit shifting) */

    apply {
        if (hdr.hulapp.isValid() && hdr.hulapp.dir == 0){

            /* pick max qdepth in hulapp forward path */
            if (hdr.hulapp.qdepth < (qdepth_t)standard_metadata.deq_qdepth){

                /* update queue length */
                hdr.hulapp.qdepth = (qdepth_t)standard_metadata.deq_qdepth;

            }


            
            /* estimating time delta to the closest power of 2 */
            bit<32> delta;
            delta = standard_metadata.deq_timedelta;
            delta = delta - 1;
            delta = delta | (delta >> 1);
            delta = delta | (delta >> 2);
            delta = delta | (delta >> 4);
            delta = delta | (delta >> 8);
            delta = delta | (delta >> 16);
            delta = delta + 1;


            /* receiving link_util metric: number of packet divided by timedelta */
            bit<39> tx_util;
            if (delta == (1 << 8)) {
                tx_util = ((bit<39>)standard_metadata.enq_qdepth << 20) >> 8;
            } else if (delta == (1 << 9)) {
                tx_util = ((bit<39>)standard_metadata.enq_qdepth << 20) >> 9;
            } else if (delta == (1 << 10)) {
                tx_util = ((bit<39>)standard_metadata.enq_qdepth << 20) >> 10;
            } else if (delta == (1 << 11)) {
                tx_util = ((bit<39>)standard_metadata.enq_qdepth << 20) >> 11;
            } else if (delta == (1 << 12)) {
                tx_util = ((bit<39>)standard_metadata.enq_qdepth << 20) >> 12;
            } else if (delta == (1 << 13)) {
                tx_util = ((bit<39>)standard_metadata.enq_qdepth << 20) >> 13;
            } else if (delta == (1 << 14)) {
                tx_util = ((bit<39>)standard_metadata.enq_qdepth << 20) >> 14;
            } else if (delta == (1 << 15)) {
                tx_util = ((bit<39>)standard_metadata.enq_qdepth << 20) >> 15;
            } else if (delta == (1 << 16)) {
                tx_util = ((bit<39>)standard_metadata.enq_qdepth << 20) >> 16;
            } else if (delta == (1 << 17)) {
                tx_util = ((bit<39>)standard_metadata.enq_qdepth << 20) >> 17;
            } else if (delta == (1 << 18)) {
                tx_util = ((bit<39>)standard_metadata.enq_qdepth << 20) >> 18;
            } else if (delta == (1 << 19)) {
                tx_util = ((bit<39>)standard_metadata.enq_qdepth << 20) >> 19;
            } else if (delta == (1 << 20)) {
                tx_util = ((bit<39>)standard_metadata.enq_qdepth << 20) >> 20;
            } else if (delta == (1 << 21)) {
                tx_util = ((bit<39>)standard_metadata.enq_qdepth << 20) >> 21;
            } else if (delta == (1 << 22)) {
                tx_util = ((bit<39>)standard_metadata.enq_qdepth << 20) >> 22;
            } else if (delta == (1 << 23)) {
                tx_util = ((bit<39>)standard_metadata.enq_qdepth << 20) >> 23;
            } else if (delta == (1 << 24)) {
                tx_util = ((bit<39>)standard_metadata.enq_qdepth << 20) >> 24;
            } else if (delta == (1 << 25)) {
                tx_util = ((bit<39>)standard_metadata.enq_qdepth << 20) >> 25;
            } else if (delta == (1 << 26)) {
                tx_util = ((bit<39>)standard_metadata.enq_qdepth << 20) >> 26;
            } else if (delta == (1 << 27)) {
                tx_util = ((bit<39>)standard_metadata.enq_qdepth << 20) >> 27;
            } else if (delta == (1 << 28)) {
                tx_util = ((bit<39>)standard_metadata.enq_qdepth << 20) >> 28;
            } else if (delta == (1 << 29)) {
                tx_util = ((bit<39>)standard_metadata.enq_qdepth << 20) >> 29;
            } else if (delta == (1 << 30)) {
                tx_util = ((bit<39>)standard_metadata.enq_qdepth << 20) >> 30;
            } else if (delta == (1 << 31)) {
                tx_util = ((bit<39>)standard_metadata.enq_qdepth << 20) >> 31;
            } else {
                bit<8> tmp = (bit<8>)delta;
                tx_util = ((bit<39>)standard_metadata.enq_qdepth << 20) >> tmp;
            }



            /* pick max path util in hulapp forward path */
            if (hdr.hulapp.path_util < tx_util) {
                /* update path util */
                hdr.hulapp.path_util = tx_util;
            }




        
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      	  hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.vlan_tag); //vs451: added vlan tag
        packet.emit(hdr.hulapp);
        packet.emit(hdr.srcRoutes);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp); //added tcp
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
