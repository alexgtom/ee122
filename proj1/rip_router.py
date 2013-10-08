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

    def delete(self, dst):
        del self.distance[dst]

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
        if host in self.t:
            # prefer host with lower port
            if port < self.t[host]:
                self.t[host] = port
        else:
            self.t[host] = port

    def del_host(self, host):
        del self.t[host]

    def values(self):
        return self.t.values()

    def __contains__(self, key):
        return key in self.t
'''
Create your RIP router in this file.
'''
class RIPRouter (Entity):
    def __init__(self):
        self.dt = DistanceTable()
        self.port_table = PortTable()

    def handle_rx (self, packet, port, send=None):
        if send == None:
            send = self.send

        if isinstance(packet, DiscoveryPacket):
            self.handle_discovery_packet(packet, port, send)
        elif isinstance(packet, RoutingUpdate):
            self.handle_routing_update(packet, port, send)
        else:
            # handle other packet
            dst = self.dt.get_via(packet.dst)
            if self.dt.get(packet.dst) != DistanceTable.INFINITY:
                send(packet, self.port_table.get_port(dst))
            else:
                # drop packet since there no path
                pass

    def handle_discovery_packet(self, packet, port, send):
        # prevent poison reverse
        exclude_ports = []
        exclude_ports.append(port)

        if packet.is_link_up:
            # if link is up, set distance to dst to infinity
            self.port_table.set(packet.src, port)
            self.dt.set(packet.src, packet.src, 1)
        else:
            # if link is down, set distance to dst to infinity
            for dst in self.dt.keys():
                self.dt.set(dst, packet.src, DistanceTable.INFINITY)

    def handle_routing_update(self, packet, port, send):
        routing_update = RoutingUpdate()
        # prevent poison reverse
        exclude_ports = []
        exclude_ports.append(port)

        for dst in packet.all_dests():
            if dst == self:
                # dont add dst to distance table if its self
                continue

            # calculate new distance
            packet_src = self.port_table.get_host(port)
            new_dist = self.dt.get(packet_src) + packet.get_distance(dst)
            if packet.get_distance(dst) >= DistanceTable.INFINITY:
                new_dist = DistanceTable.INFINITY
            
            # add to routing update if the new_dist is better than the current one
            if new_dist < self.dt.get(dst):
                routing_update.add_destination(dst, new_dist)
            
            # set new distance
            self.dt.set(dst, packet_src, new_dist)

        if len(routing_update.all_dests()) > 0:
            send(routing_update, exclude_ports, flood=True)
