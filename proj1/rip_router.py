from sim.api import *
from sim.basics import *

class DistanceTable(object):
    def __init__(self):
        self.distance = {}

    def set(self, dest, via, distance):
        if self.distance.get(dest) == None:
            self.distance[dest] = {}
        self.distance[dest][via] = distance

    def get(self, dest, via=None):
        if via:
            return self.distance[dest][via]
        else:
            return min(self.distance[dest].values())

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
