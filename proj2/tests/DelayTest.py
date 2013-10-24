import random
import time
import math
from time import *
from BasicTest import *

DELAY_TIME = 0.1

#This test delays every transmission by 100 ms... how rude.

class DelayTest(BasicTest):
    def sin_delay(self):
        curr_time = time()
        ret = 0.1 * ((.15 * math.sin(curr_time/2)) + .35)
        return ret

    def handle_packet(self):
        for p in self.forwarder.in_queue:
            sleep(self.sin_delay())
            self.forwarder.out_queue.append(p)
        self.forwarder.in_queue=[]
