from sim.api import *
from sim.basics import *

class DistanceTable(object):
    INFINITY = 100

    def __init__(self):
        self.distance = {}

    def set(self, dst, via, distance):
        if self.distance.get(dst) == None:
            self.distance[dst] = {}
        self.distance[dst][via] = distance

    def get(self, dst, via=None):
        try:
            self.distance[dst]
        except KeyError:
            return self.INFINITY

        if via:
            return self.distance[dst][via]
        else:
            return min(self.distance[dst].values())

    def get_via(self, dst):
        d = self.distance[dst]
        return min(d, key=d.get)

    def values(self):
        return self.distance.values()

    def keys(self):
        return self.distance.keys()

    def __contains__(self, key):
        return key in self.distance

    def __str__(self):
        s = ""
        s += "dst: distances\n"
        for key in self.distance:
            s += str(key) + " :::: " + str(self.distance[key]) + "\n"
        return s

    def __len__(self):
        return len(self.distance)

class PortTable(object):
    def __init__(self):
        self.t = {}

    def get_port(self, host):
        return self.t[host]

    def get_host(self, port):
        for key, value in self.t.iteritems():
            if value == port:
                return key
        raise KeyError

    def set(self, host, port):
        self.t[host] = port

    def del_host(self, host):
        del self.t[host]

    def values(self):
        return self.t.values()
'''
Create your RIP router in this file.
'''
class RIPRouter (Entity):
    def __init__(self):
        self.dt = DistanceTable()
        self.port_table = PortTable()

    def handle_rx (self, packet, port):
        if isinstance(packet, DiscoveryPacket):
            self.handle_discovery_packet(packet, port)
        elif isinstance(packet, RoutingUpdate):
            self.handle_routing_update(packet, port)
        else:
            # handle other packet
            dst = self.dt.get_via(packet.dst)
            self.send(packet, self.port_table.get_port(dst))


    def handle_discovery_packet(self, packet, port):
        if packet.is_link_up:
            # if link is up, set distance to dst to infinity
            self.port_table.set(packet.src, port)
            self.dt.set(packet.src, packet.src, 1)
        else:
            # if link is down, set distance to dst to infinity
            self.dt.set(packet.src, packet.src, DistanceTable.INFINITY)
            self.port_table.del_host(packet.src)

        # send routing update
        routing_update = RoutingUpdate()
        for dst in self.dt.keys():
            routing_update.add_destination(dst, self.dt.get(dst))
        self.send(routing_update, port=self.port_table.values())

    def handle_routing_update(self, packet, port):
        routing_update = RoutingUpdate()
        for dst in packet.all_dests():
            if dst == self:
                # dont add dst to distance table if its self
                continue

            packet_src = self.port_table.get_host(port)
            new_dist = self.dt.get(packet_src) + packet.get_distance(dst)
            
            # add to routing update if the new_dist is better than the current one
            if new_dist < self.dt.get(dst):
                routing_update.add_destination(dst, new_dist)
            
            # set new distance
            self.dt.set(dst, packet_src, new_dist)

        if len(routing_update.all_dests()) > 0:
            self.send(routing_update, port=self.port_table.values())
