from sim.api import *
from sim.basics import *

class DistanceTable(object):
    def __init__(self):
        self.distance = {}

    def set(self, dst, via, distance):
        if self.distance.get(dst) == None:
            self.distance[dst] = {}
        self.distance[dst][via] = distance

    def get(self, dst, via=None):
        if via:
            return self.distance[dst][via]
        else:
            return min(self.distance[dst].values())

'''
Create your RIP router in this file.
'''
class RIPRouter (Entity):
    def __init__(self):
        # Add your code here!
        pass

    def handle_rx (self, packet, port):
        # Add your code here!
        raise NotImplementedError
