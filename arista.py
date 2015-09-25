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
import time, json, yaml

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

class Faucet(app_manager.RyuApp):
    """A Ryu app that performs layer 2 switching with VLANs.

    The intelligence is largely provided by a Valve class. Faucet's role is
    mainly to perform set up and to provide a communication layer between ryu
    and valve.
    """
    OFP_VERSIONS = [ofp.OFP_VERSION]

    _CONTEXTS = {'dpset': dpset.DPSet}

    logname = 'faucet'
    exc_logname = logname + '.exception'

    def __init__(self, *args, **kwargs):
        super(Faucet, self).__init__(*args, **kwargs)

    def get_group_id(self, vlan_vid, port=None):
        if port is None:
            # no port indicates this is a flood group
            return  (4 << 28) | (vlan_vid << 16)
        else:
            return  (vlan_vid << 16) | port

    def send_flow_mod(self, dp, mod):
        jsondict = mod.to_jsondict()
        print json.dumps(jsondict, indent=4)
        dp.send_msg(mod)


    def print_mod(self, mod):
        jsondict = mod.to_jsondict()
        print json.dumps(jsondict, indent=4)

    def send_group_mod(self, dp, mod):
        jsondict = mod.to_jsondict()
        print json.dumps(jsondict, indent=4)
        dp.send_msg(mod)

        match = parser.OFPMatch()
        req = parser.OFPFlowStatsRequest(
            dp, 0, ofp.OFPTT_ALL, ofp.OFPP_ANY, ofp.OFPG_ANY, 0, 0, match)
        dp.send_msg(req)
        print ""
        time.sleep(3)
        print "==========================================="

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
        jsondict = ev.msg.to_jsondict()
        print json.dumps(jsondict, indent=4)

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def handler_datapath(self, ev):
        dp = ev.dp

        if not ev.enter:
            # Datapath down message
            self.valve.datapath_disconnect(dp.id)
            returnall

        # Delete things
        mod = parser.OFPFlowMod(
            datapath=dp,
            cookie=cookie,
            command=ofp.OFPFC_DELETE,
            out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY,
            match=match_all
            )
        dp.send_msg(mod)
        self.print_mod(mod)

        with open('tests.yaml', 'r') as stream:
            tests = yaml.load_all(stream)
            for test in tests:
                if 'group' in test:
                    buckets = self.create_buckets(dp, test)
                    mod=parser.OFPGroupMod(
                        datapath=dp,
                        group_id=test['group'],
                        type_=group_types[test.setdefault('type', 'all')],
                        buckets=buckets
                        )
                    dp.send_msg(mod)
                    self.print_mod(mod)
                else:
                    match = self.create_match(dp, test)
                    instructions = self.create_instructions(dp, test)
                    mod = parser.OFPFlowMod(
                        datapath=dp,
                        cookie=cookie,
                        match=match,
                        instructions=instructions
                        )
                    dp.send_msg(mod)
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

    def create_match(self, dp, test):
        return ofctl_v1_3.to_match(dp, test['match'])

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
                    result.append(parser.OFPActionOutput(int(v)))
                elif k == 'group':
                    result.append(parser.OFPActionGroup(int(v)))
                elif k == 'push_vlan':
                    result.append(parser.OFPActionPushVlan(ether.ETH_TYPE_8021Q))
                    vlan_vid = v | ofproto_v1_3.OFPVID_PRESENT
                    result.append(parser.OFPActionSetField(vlan_vid=vlan_vid))
                elif k == 'pop_vlan':
                    result.append(parser.OFPActionPopVlan())
        return result

    def delete_all(self, args):
        print "test delete"
        mod = parser.OFPFlowMod(
            datapath=dp,
            cookie=cookie,
            command=ofp.OFPFC_DELETE,
            out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY,
            match=match_all
            )
        dp.send_msg(dp, mod)

    def drop_all(self, args):
        print "test drop"
        mod = parser.OFPFlowMod(
            datapath=dp,
            cookie=cookie,
            priority=low_priority,
            match=match_all,
            instructions=[]
            )
        self.send_flow_mod(dp, mod)

    def apply_output(self, args):
        print "test apply output"
        inst = parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [action_2])
        mod = parser.OFPFlowMod(
            datapath=dp,
            cookie=cookie,
            priority=high_priority,
            match=match_1,
            instructions=[inst]
            )
        self.send_flow_mod(dp, mod)

    def write_output(self, args):
        print "test write output"
        inst = parser.OFPInstructionActions(ofp.OFPIT_WRITE_ACTIONS, [action_2])
        mod = parser.OFPFlowMod(
            datapath=dp,
            cookie=cookie,
            priority=high_priority,
            match=match_1,
            instructions=[inst]
            )
        self.send_flow_mod(dp, mod)

    def match_mac(self, args):
        print "test mac match"
        mod = parser.OFPFlowMod(
            datapath=dp,
            cookie=cookie,
            priority=highest_priority,
            match=match_eth_dst,
            instructions=[]
            )
        self.send_flow_mod(dp, mod)

        print "test flow override"
        mod = parser.OFPFlowMod(
            datapath=dp,
            cookie=cookie,
            priority=highest_priority,
            match=match_eth_dst,
            instructions=[inst]
            )
        self.send_flow_mod(dp, mod)


        print "test multiple outputs"
        inst = parser.OFPInstructionActions(
            ofp.OFPIT_APPLY_ACTIONS,
            [action_2, action_controller]
            )
        mod = parser.OFPFlowMod(
            datapath=dp,
            cookie=cookie,
            priority=highest_priority,
            match=match_eth_dst,
            instructions=[inst]
            )
        self.send_flow_mod(dp, mod)

        print "l2interface group"
        gid_2 = self.get_group_id(vid, 2)
        bucket = parser.OFPBucket(
            watch_port=2,
            actions=[action_2]
            )
        mod = parser.OFPGroupMod(
            datapath=dp,
            type_=ofp.OFPGT_INDIRECT,
            group_id=gid_2,
            buckets=[bucket]
            )
        self.send_group_mod(dp, mod)

        print "now use it"
        mod = parser.OFPFlowMod(
            datapath=dp,
            cookie=cookie,
            priority=highest_priority,
            match=match_eth_dst,
            instructions=[
                parser.OFPInstructionActions(   ofp.OFPIT_APPLY_ACTIONS,
                                                [parser.OFPActionGroup(gid_2)]
                                                )
                ]
            )
        self.send_flow_mod(dp, mod)

        print "l2interface group with vlan"
        gid_3 = self.get_group_id(vid, 3)
        actions_push_vlan_3 = [
            parser.OFPActionPushVlan(ether.ETH_TYPE_8021Q),
            parser.OFPActionSetField(vlan_vid=vid|ofp.OFPVID_PRESENT),
            action_3
            ]
        bucket = parser.OFPBucket(
            watch_port=3,
            actions=actions_push_vlan_3
            )
        mod = parser.OFPGroupMod(
            datapath=dp,
            type_=ofp.OFPGT_INDIRECT,
            group_id=gid_3,
            buckets=[bucket]
            )
        self.send_group_mod(dp, mod)

        print "l2flood group"
        # Make some buckets
        bucket = parser.OFPBucket(
            actions=[parser.OFPActionGroup(gid_2)],
            watch_group=gid_2
            )
        flood_buckets = [bucket]

        bucket = parser.OFPBucket(
            actions=[parser.OFPActionGroup(gid_3)],
            watch_group=gid_3
            )
        flood_buckets.append(bucket)

        # now make the flood group
        gid = self.get_group_id(vid)
        mod = parser.OFPGroupMod(
            datapath=dp,
            type_=ofp.OFPGT_ALL,
            group_id=gid,
            buckets=[bucket]
            )
        self.send_group_mod(dp, mod)
