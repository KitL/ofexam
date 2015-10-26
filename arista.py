# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Innovation Advanced Network New Zealand Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os, signal, logging
import time, json, yaml, array, threading

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ether
from ryu.ofproto import ofproto_v1_3 as ofp
from ryu.ofproto import ofproto_v1_3_parser as parser
from ryu.lib import ofctl_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import vlan
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp

# some default values
vid = 2040
low_priority = 10
high_priority = 100
highest_priority = 1000
cookie = 55665

group_types = {
    'all': ofp.OFPGT_ALL,
    'select': ofp.OFPGT_SELECT,
    'indirect': ofp.OFPGT_INDIRECT,
    'ff': ofp.OFPGT_FF
    }
# some matches
match_all = parser.OFPMatch()
match_1 = parser.OFPMatch(in_port=1)
match_eth_dst = parser.OFPMatch(eth_dst="00:00:00:00:00:01")

# some actions
action_2 = parser.OFPActionOutput(2)
action_3 = parser.OFPActionOutput(3)
action_controller = parser.OFPActionOutput(ofp.OFPP_CONTROLLER)

class SwitchTester(app_manager.RyuApp):
    OFP_VERSIONS = [ofp.OFP_VERSION]

    _CONTEXTS = {'dpset': dpset.DPSet}

    def __init__(self, *args, **kwargs):
        super(SwitchTester, self).__init__(*args, **kwargs)
        self.outcomes = {}
        self.ovs_dp = None
        self.dut_dp = None

    def print_mod(self, mod):
        jsondict = mod.to_jsondict()
        print json.dumps(jsondict, indent=4)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        jsondict = ev.msg.to_jsondict()
        print "flow stats reply:"
        print json.dumps(jsondict, indent=4)

    @set_ev_cls(ofp_event.EventOFPGroupStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        jsondict = ev.msg.to_jsondict()
        print "group stats reply:"
        print json.dumps(jsondict, indent=4)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        print "packet in {0}".format(ev.msg.datapath.id)
        jsondict = ev.msg.to_jsondict()
        print json.dumps(jsondict, indent=4)

        pkt = packet.Packet(array.array('B', ev.msg.data))
        self.print_packet(pkt)
        if ev.msg.cookie in self.outcomes:
            self.outcomes[ev.msg.cookie] = True
        else:
            self.outcomes[999] = False
            print "received unexpected packet"

    def print_packet(self, pkt):
        for p in pkt.protocols:
            print p

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def handler_datapath(self, ev):
        dp = ev.dp
        print "new datapath!"

        # Delete things
        mod = parser.OFPFlowMod(
            datapath=dp,
            command=ofp.OFPFC_DELETE,
            out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY,
            match=match_all
            )
        dp.send_msg(mod)
        self.print_mod(mod)

        if dp.id == 17:
            self.ovs_dp = dp
        else:
            self.dut_dp = dp

        if self.ovs_dp is not None and self.dut_dp is not None:
            self.send_flows()
            time.sleep(1)
            self.initiate_test()
            def check_outcomes(test):
                if all(self.outcomes.values()):
                    print "test successful!"
                else:
                    for cookie, outcome in self.outcomes.iteritems():
                        if not outcome:
                            print "outcome not satisfied: {0}".format(cookie)
            test_thread = threading.Timer(5, check_outcomes, args=[self.test])
            test_thread.start()


    def match_to_packet(self, match):
        pkt = packet.Packet()
        l2 = ethernet.ethernet(
            dst=match.setdefault('eth_dst', "00:00:00:00:00:02"),
            src=match.setdefault('eth_src', "00:00:00:00:00:01"),
            ethertype=match.setdefault('eth_type', 0x800)
            )
        pkt.add_protocol(l2)
        if 'vlan_vid' in match:
            pkt.get_protocol(ethernet.ethernet).ethertype=0x8100
            vl = vlan.vlan(
                pcp=0,
                cfi=0,
                vid=match['vlan_vid'],
                ethertype=match['eth_type']
                )
            pkt.add_protocol(vl)
        l3 = ipv4.ipv4(
            src=match.setdefault('ipv4_src', "192.168.1.1"),
            dst=match.setdefault('ipv4_dst', "192.168.1.2")
            )
        pkt.add_protocol(l3)
        l4 = tcp.tcp(
            src_port=match.setdefault('tcp_src', 12345),
            dst_port=match.setdefault('tcp_dst', 80)
            )
        pkt.add_protocol(l4)

        pkt.serialize()
        return pkt

    def initiate_test(self):
        pkt = self.match_to_packet(self.test['match'])
        time.sleep(.2)

        print "sending packet:"
        self.print_packet(pkt)
        actions = parser.OFPActionOutput(self.test['match'].setdefault('in_port', 1))
        msg = parser.OFPPacketOut(
            self.ovs_dp,
            buffer_id=ofp.OFP_NO_BUFFER,
            in_port=ofp.OFPP_CONTROLLER,
            data=pkt.data,
            actions=[actions]
            )
        self.ovs_dp.send_msg(msg)

    def send_flows(self):
        # send default packet in for ovs
        mod = parser.OFPFlowMod(
            datapath=self.ovs_dp,
            cookie=cookie,
            priority=low_priority,
            match=match_all,
            instructions=[
                parser.OFPInstructionActions(
                    ofp.OFPIT_APPLY_ACTIONS,
                    [action_controller]
                    )
                ]
            )
        self.ovs_dp.send_msg(mod)

        with open('tests.yaml', 'r') as stream:
            flows = yaml.load_all(stream)
            for flow in flows:
                print flow
                t = flow['type']
                if t == 'group' :
                    buckets = self.create_buckets(self.dut_dp, flow)
                    mod=parser.OFPGroupMod(
                        datapath=self.dut_dp,
                        group_id=flow['id'],
                        type_=group_types[flow.setdefault('group_type', 'all')],
                        buckets=buckets
                        )
                    self.dut_dp.send_msg(mod)
                    self.print_mod(mod)
                elif t == 'flow':
                    match = self.create_match(self.dut_dp, flow['match'])
                    instructions = self.create_instructions(self.dut_dp, flow)
                    mod = parser.OFPFlowMod(
                        datapath=self.dut_dp,
                        cookie=cookie,
                        match=match,
                        instructions=instructions
                        )
                    self.dut_dp.send_msg(mod)
                    self.print_mod(mod)
                elif t == 'test':
                    self.test = flow
                elif t == 'outcome':
                    self.outcomes[flow['cookie']] = False
                    match = self.create_match(self.ovs_dp, flow['match'])
                    instructions = parser.OFPInstructionActions(
                        ofp.OFPIT_APPLY_ACTIONS,
                        [action_controller]
                        )
                    mod = parser.OFPFlowMod(
                        datapath=self.ovs_dp,
                        cookie=flow['cookie'],
                        priority=high_priority,
                        match=match,
                        instructions=[instructions]
                        )
                    self.ovs_dp.send_msg(mod)
                    self.print_mod(mod)

    def create_buckets(self, dp, test):
        buckets = []
        for bucket in test['buckets']:
            actions = self.create_actions(bucket['actions'])
            buckets.append(parser.OFPBucket(
                weight=bucket.setdefault('weight', 10),
                watch_port=bucket.setdefault('watch_port', ofp.OFPP_ANY),
                watch_group=bucket.setdefault('watch_group', ofp.OFPG_ANY),
                actions=actions
                ))
        return buckets

    def create_match(self, dp, match):
        return ofctl_v1_3.to_match(dp, match)

    def create_instructions(self, dp, test):
        # ryu doesnt seem to include instruction parsing
        instructions = []
        if 'write_actions' in test:
            actions = self.create_actions(test['write_actions'])
            instructions.append(parser.OFPInstructionActions(ofp.OFPIT_WRITE_ACTIONS, actions))
        if 'apply_actions' in test:
            actions = self.create_actions(test['apply_actions'])
            instructions.append(parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions))
        if 'goto_table' in test:
            instructions.append(parser.OFPInstructionGotoTable(test['goto_table']))
        return instructions

    def create_actions(self, action_list):
        result = []
        # ryu to_action is horrible
        for act in action_list:
            # act should be a single entry dict
            for k, v in act.iteritems():
                if k == 'output':
                    if v == 'controller':
                        result.append(action_controller)
                    else:
                        result.append(parser.OFPActionOutput(int(v)))
                elif k == 'group':
                    result.append(parser.OFPActionGroup(int(v)))
                elif k == 'push_vlan':
                    result.append(parser.OFPActionPushVlan(ether.ETH_TYPE_8021Q))
                    vlan_vid = v | ofp.OFPVID_PRESENT
                    result.append(parser.OFPActionSetField(vlan_vid=v))
                elif k == 'pop_vlan':
                    result.append(parser.OFPActionPopVlan())
        return result
