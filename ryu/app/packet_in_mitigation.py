from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

from ryu.lib import ofctl_v1_3
import time

# should be set by CONF file
MITIGATE_TIME_INTERVAL=1
MAX_PKTIN_COUNT=10
DROP_INTERVAL=10

class PacketInMitigation(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        # key: (dpid, in_port), value: list of count, last_time
        self.pktin_counter = {}
        self.time_interval = MITIGATE_TIME_INTERVAL
        self.max_pktin_count = MAX_PKTIN_COUNT
        self.drop_interval = DROP_INTERVAL
        super(PacketInMitigation, self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id

        self._update_counter(dpid, in_port)
        if self._is_counter_over(dpid, in_port):
            # set drop flow for packet-in message if counter is over
            self.logger.debug('stop!!!')
            self._set_drop_flow(datapath, in_port)

    def _update_counter(self, dpid, in_port):
        '''
        Update packet_in_counter
        '''
        interval = self.time_interval
        curr_time = ( int(time.time()) / interval ) * interval
        if not self.pktin_counter.has_key((dpid, in_port)):
            self.pktin_counter[(dpid, in_port)] = [1, curr_time]
            return
        else:
            if curr_time != self.pktin_counter[(dpid, in_port)][1]:
                self.pktin_counter[(dpid, in_port)] = [1, curr_time]
            else:
                self.pktin_counter[(dpid, in_port)][0] += 1

    def _is_counter_over(self, dpid, in_port):
        '''
        Return True if packet_in_counter is over
        '''
        interval = self.time_interval
        curr_time = ( int(time.time()) / interval ) * interval
        if (self.pktin_counter[(dpid, in_port)][1] == curr_time and
            self.pktin_counter[(dpid, in_port)][0] > self.max_pktin_count):
            self.logger.info('stop packet_in handler dpid=%s in_port=%s',
                             dpid, in_port)
            return True
        else:
            return False

    def _set_drop_flow(self, datapath, in_port):
        '''
        Set drop flow
        TODO: handle inport or mac or IP etc...
        '''
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        priority = 10000  # TODO: should not use fix value
        match = parser.OFPMatch(in_port=in_port)
        actions = []
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                hard_timeout=self.drop_interval,
                                match=match, instructions=inst)
        datapath.send_msg(mod)
        self.logger.debug('send drop flow: dpid=%s in_port=%s',
                          datapath.id, in_port)
