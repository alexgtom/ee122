#!/bin/env python

import sys
sys.path.append('.')

from sim.api import *
from sim.basics import *
from rip_router import RIPRouter
import sim.topo as topo
import os
import time

#failed = False
failed = True
msg = ''

class FakeEntity (Entity):
    def __init__(self, expected, to_announce):
        self.expect = expected
        self.announce = to_announce
        self.num_rx = 0
        if(self.announce):
            self.timer = create_timer(5, self.send_announce)    
            

    def handle_rx(self, packet, port):
        global failed
        global received
	global msg
        failed = False
        msg = ''
        if(self.expect):
            if(isinstance(packet, RoutingUpdate)):
                self.num_rx += 1
                for dest, cost in packet.paths.iteritems():
                  if dest not in self.expect.keys():
                    failed = True
                    msg = msg + str((dest, cost))
                  elif cost != self.expect[dest]:
                    failed = True
                    msg = msg + str((dest, cost))
                

    def send_announce(self):
        if(self.announce):
            update = RoutingUpdate()
            for dest, cost in self.announce.iteritems():
              update.add_destination(dest, cost)
            self.send(update, flood=True)

def create (switch_type = FakeEntity, host_type = FakeEntity, n = 2):
    RIPRouter.create('A')
    RIPRouter.create('B')
    #RIPRouter.create('C')
    #RIPRouter.create('D')
    RIPRouter.create('E')
    FakeEntity.create('Z', {A: 1}, {})
    topo.link(A, B)
    #topo.link(B, C)
    #topo.link(C, D)
    #topo.link(D, E)
    topo.link(B, E)
    topo.link(B, Z)
    #topo.link(C, Z)
    
import sim.core
from hub import Hub as switch

import sim.api as api
import logging
api.simlog.setLevel(logging.DEBUG)
api.userlog.setLevel(logging.DEBUG)

_DISABLE_CONSOLE_LOG = True

create(switch)
start = sim.core.simulate
start()
time.sleep(5)
topo.unlink(B, E)
time.sleep(5)
if(failed):
  print("You have failed since I got unexpected updates!")
  print(msg)
  os._exit(0)
else:
  print("Test is successful!")
  os._exit(2)
