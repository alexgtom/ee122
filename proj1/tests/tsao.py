#!/bin/env python

import sys
sys.path.append('.')

from sim.api import *
from sim.basics import *
from rip_router import RIPRouter
import sim.topo as topo
import os
import time

testing = True
failed = False
waittime = 5
expectedUpdate1 = {}
expectedSender1 = {}

class FakeEntity (Entity):
    def __init__(self, expectedUpdate, expectedSender, to_announce):
        self.expectedUpdate = expectedUpdate
        self.expectedSender = expectedSender
        self.announce = to_announce
        self.num_rx = 0
        #if(self.announce):
        #    self.timer = create_timer(5, self.send_announce)    

    def handle_rx(self, packet, port):
        global failed
        global testing
        if(self.expectedUpdate):
            if(isinstance(packet, RoutingUpdate)):
                self.num_rx += 1
                if not testing:
                    print "PACKET! "+str(packet.src)
                    if len(packet.paths) == 0:
                        print "  EMPTY!"
                    for dest, cost in packet.paths.iteritems():
                        print "  "+str(dest)+","+str(cost)
                    return
                print "Packet received: "+str(self.num_rx)
                if not self.expectedUpdate.has_key(self.num_rx):
                    print "FAILED: extra packet sent by "+str(packet.src)
                    failed = True
                elif (packet.src != self.expectedSender[self.num_rx]):
                    print "FAILED: Sent by "+str(packet.src)+", should be "+str(self.expectedSender[self.num_rx])
                    failed = True
                elif len(packet.paths) > len(self.expectedUpdate[self.num_rx]):
                    print "FAILED: Too many items in packet: "+str(packet.paths)+", should be "+str(self.expectedUpdate[self.num_rx])
                    failed = True
                elif len(packet.paths) < len(self.expectedUpdate[self.num_rx]):
                    print "FAILED: Too few items in packet: "+str(packet.paths)+", should be "+str(self.expectedUpdate[self.num_rx])
                    failed = True
                else:
                    for dest,cost in packet.paths.iteritems():
                        if dest not in self.expectedUpdate[self.num_rx].keys():
                            print "FAILED: destination "+str(dest)+" not expected to be in packet."
                            failed = True
                        elif cost != self.expectedUpdate[self.num_rx][dest]:
                            print "FAILED: cost "+str(cost)+" for destination "+str(dest)+" incorrect, should be "+str(self.expectedUpdate[self.num_rx][dest])
                            failed = True

                  #if dest not in self.expectedUpdate.keys():
                  #  failed = True
                  #elif cost != self.expectedUpdate[dest]:
                  #  failed = True

    def send_announce(self):
        pass
        #if(self.announce):
        #    update = RoutingUpdate()
        #    for dest, cost in self.announce.iteritems():
        #      update.add_destination(dest, cost)
        #    self.send(update, flood=True)

    def send_specific_announce(self, announce):
        if(announce):
            update = RoutingUpdate()
            for dest, cost in announce.iteritems():
              update.add_destination(dest, cost)
            self.send(update, flood=True)

def create (switch_type = FakeEntity, host_type = FakeEntity, n = 2):
    global expectedUpdate1
    global expectedSender1
    global waittime

    print "Creating routers..."
    RIPRouter.create('A')
    RIPRouter.create('B')
    RIPRouter.create('C')
    RIPRouter.create('D')
    RIPRouter.create('E')
    RIPRouter.create('F')
    RIPRouter.create('G')
    RIPRouter.create('H')
    RIPRouter.create('I')
    RIPRouter.create('J')
    createExpectedDict()
    FakeEntity.create('Z', expectedUpdate1, expectedSender1, {})
    
    
    print "Case 1: A-B-Z"
    topo.link(A, B)      #A - B - Z
    topo.link(B, Z)
    time.sleep(waittime)
    if(failed):
        return
    
    print "Case 2: A B-Z"
    topo.unlink(A, B)    #A   B - Z
    time.sleep(waittime)
    if(failed):
        return
    
    print "Case 3: A-B Z"
    topo.unlink(B, Z)
    time.sleep(waittime/2)
    topo.link(A, B)      #A - B   Z
    time.sleep(waittime)
    if(failed):
        return
    
    print "Case 4: A-B-C-D-E-Z"
    topo.link(E, Z)      #A - B - C - D - E - Z
    topo.link(B, C)
    topo.link(C, D)
    time.sleep(waittime)
    topo.link(D, E)
    time.sleep(waittime)
    if(failed):
        return
    
    print "Case 5: Circle(A,E)-Z"
    topo.link(E, A)      #A - B - C - D - E - Z
    time.sleep(waittime) # \_____________/
    if(failed):
        return

    print "Case 6: Clique(A,E)-Z"
    #topo.link(A, B)
    topo.link(A, C)
    topo.link(A, D)
    #topo.link(A, E)
    #topo.link(B, C)
    topo.link(B, D)      #        ---A---
    topo.link(B, E)      #       /  / \  \ 
    time.sleep(waittime) #      B--|---|-E -- Z   
    #topo.link(C, D)     #       \ |/ \| /
    topo.link(C, E)      #        C-----D
    #topo.link(D, E)     #   Clique
    time.sleep(waittime)
    if(failed):
        return

    print "Case 7: Centralize(A,{B,C,D,E,Z}"
    #topo.unlink(A, B)
    #topo.unlink(A, C)
    #topo.unlink(A, D)
    #topo.unlink(A, E)
    topo.unlink(E, Z)
    topo.unlink(B, C)
    topo.unlink(B, D)    #           Z
    topo.unlink(B, E)    #           |    
    topo.unlink(C, D)    #      B -- A -- E
    topo.unlink(C, E)    #          / \  
    topo.unlink(D, E)    #        C     D
    time.sleep(waittime)
    topo.link(A, Z)
    time.sleep(waittime)
    if(failed):
        return
    
    print "Case 8: Centralize(A,Circle(B-E,Z))"
    topo.link(B, C)      
    topo.link(C, D)      
    topo.link(D, E)      
    time.sleep(waittime)    #       ---Z---
    topo.link(E, Z)         #      /   |   \ 
    time.sleep(waittime/2)  #     B -- A -- E
    topo.link(Z, B)         #      \  / \  /
    time.sleep(waittime)    #       C-----D
    if(failed):
        return
    
    print "Case 9: A-B-Branch(Z, C-D-E, F-G)"
    topo.unlink(A, Z)
    topo.unlink(E, Z)
    topo.unlink(B, Z)
    #topo.unlink(A, B)
    topo.unlink(A, C)
    topo.unlink(A, D)
    topo.unlink(A, E)
    topo.unlink(B, C)
    topo.link(F, G)
    #print "REM"
    #topo.unlink(C, D)
    #topo.unlink(D, E)  
    time.sleep(waittime) 
    topo.link(B, Z)      
    time.sleep(waittime/2)
    Z.send_specific_announce({F: 1, G: 2, C: 1, D: 2, E: 3})
    time.sleep(waittime/2)
    topo.unlink(B, Z)      
    topo.link(Z, C)        
    time.sleep(waittime/2)
    Z.send_specific_announce({F: 1, G: 2, B: 1, A: 2})
    time.sleep(waittime/2)   #             
    topo.unlink(C, Z)        #             F - G
    topo.link(Z, F)          #             |
    time.sleep(waittime/2)   #     A - B - Z - C - D - E 
    Z.send_specific_announce({B: 1, A: 2, C: 1, D: 2, E: 3})    
    time.sleep(waittime/2)
    topo.unlink(F, G)
    Z.send_specific_announce({B: 1, A: 2, C: 1, D: 2, E: 3, G: 100})
    #print "NIM"
    time.sleep(waittime/2)
    topo.link(F, G)
    time.sleep(waittime)
    if(failed):
        return

    print "Case 10: EShaped(ABC,EHD,FGZ)"
    #topo.unlink(B, Z)
    #topo.unlink(Z, C)
    topo.unlink(Z, F)
    #topo.unlink(A, B)
    topo.unlink(C, D)
    topo.unlink(D, E)
    #topo.unlink(F, G)
    topo.link(B, C)
    topo.link(A, E)      #     A ------B------C
    topo.link(E, H)      #     |
    topo.link(H, D)      #     E ------H------D
    topo.link(A, F)      #     |
    time.sleep(waittime) #     F-------G------Z
    topo.link(G, Z)      
    time.sleep(waittime/2)
    topo.disconnect(H)
    time.sleep(waittime)
    if(failed):
        return
    
    A.remove()
    B.remove()
    C.remove()
    D.remove()
    E.remove()
    F.remove()
    G.remove()
    H.remove()
    I.remove()
    J.remove()
    Z.remove()
    
def createExpectedDict():
    global expectedUpdate1
    global expectedSender1
    expectedUpdate1[1] = {A: 1}
    expectedSender1[1] = B
    
    expectedUpdate1[2] = {}
    expectedSender1[2] = B
    
    expectedUpdate1[3] = {}
    expectedSender1[3] = E
    expectedUpdate1[4] = {D: 1}
    expectedSender1[4] = E
    expectedUpdate1[5] = {A: 4, B: 3, C: 2, D: 1}
    expectedSender1[5] = E
    
    expectedUpdate1[6] = {A: 1, B: 3, C: 2, D: 1}
    expectedSender1[6] = E
    expectedUpdate1[7] = {A: 1, B: 2, C: 2, D: 1}
    expectedSender1[7] = E
    
    expectedUpdate1[8] = {A: 1, B: 1, C: 2, D: 1}
    expectedSender1[8] = E
    expectedUpdate1[9] = {A: 1, B: 1, C: 1, D: 1}
    expectedSender1[9] = E
    
    expectedUpdate1[10] = {B: 1, C: 1, D: 1, E: 1}
    expectedSender1[10] = A
    
    expectedUpdate1[11] = {A: 1, B: 2, C: 2, D: 1}
    expectedSender1[11] = E
    expectedUpdate1[12] = {A: 1, C: 1, D: 2, E: 2}
    expectedSender1[12] = B
    
    expectedUpdate1[13] = {A: 1}
    expectedSender1[13] = B
    expectedUpdate1[14] = {A: 1, C: 100, D: 100, E: 100, F: 100, G: 100}
    expectedSender1[14] = B
    expectedUpdate1[15] = {D: 1, E: 2}
    expectedSender1[15] = C
    expectedUpdate1[16] = {A: 100, B: 100, D: 1, E: 2, F: 100, G: 100}
    expectedSender1[16] = C
    expectedUpdate1[17] = {G: 1}
    expectedSender1[17] = F
    expectedUpdate1[18] = {A: 100, B: 100, C: 100, D: 100, E: 100, G: 1}
    expectedSender1[18] = F
    expectedUpdate1[19] = {A: 100, B: 100, C: 100, D: 100, E: 100}
    expectedSender1[19] = F
    expectedUpdate1[20] = {A: 100, B: 100, C: 100, D: 100, E: 100, G: 1}
    expectedSender1[20] = F
    
    expectedUpdate1[21] = {A: 2, B: 3, C: 4, D: 5, E: 3, F: 1, H: 4}
    expectedSender1[21] = G
    expectedUpdate1[22] = {A: 2, B: 3, C: 4, E: 3, F: 1}
    expectedSender1[22] = G
    #print str(expectedUpdate1)

import sim.core
from hub import Hub as switch

import sim.api as api
import logging
#api.simlog.setLevel(logging.DEBUG)
api.simlog.setLevel(logging.WARNING)   #So INFO messages don't show up.
api.userlog.setLevel(logging.DEBUG)

_DISABLE_CONSOLE_LOG = True


start = sim.core.simulate
start()

create(switch)





if(failed):
  print("You have failed since I got unexpected updates!")
  os._exit(0)
else:
  print("Test is successful!")
  os._exit(2)
