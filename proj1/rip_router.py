from sim.api import *
from sim.basics import *

class DistanceTable(object):
    INFINITY = 100

    def __init__(self):
        self.distance = {}

    def set(self, dst, via, distance):
        """ returns true if there is a new minimum for dst """
        if self.distance.get(dst) == None:
            self.distance[dst] = {}
            old_dist = self.INFINITY
        else:
            old_dist = self.get(dst)

        if distance >= self.INFINITY:
            self.distance[dst][via] = self.INFINITY
        else:
            self.distance[dst][via] = distance

        new_dist = self.get(dst)

        return new_dist < old_dist

    def get(self, dst, via=None):
        try:
            self.distance[dst]
        except KeyError:
            return self.INFINITY

        if via:
            return self.distance[dst][via]
        else:
            return min(self.distance[dst].values())

    def get_via_list(self, dst):
        return self.distance[dst].keys()

    def get_via(self, dst):
        d = self.distance[dst]
        return min(d, key=d.get)

    def get_num_via(self, dst):
        return len(self.distance[dst])

    def has_via(self, dst, via):
        return via in self.distance[dst]

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

    def keys(self):
        return self.t.keys()

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
        print "** handle_rx"
        print self
        print packet
        print port
        
        # list of nodes that should be included in next update
        self.update_list = []

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
        print "handle_discovery_packet"
        if packet.is_link_up:
            self.port_table.set(packet.src, port)
            new_dist = 1
        else:
            self.port_table.del_host(packet.src)
            new_dist = DistanceTable.INFINITY

        if self.dt.get(packet.src, packet.src) != new_dist:
            for dst in self.dt.keys():
                self.set(dst, packet.src, new_dist + self.dt.get(dst))

    def handle_routing_update(self, packet, port, send):
        print "handle_routing_update"
        for dst in packet.all_dests():
            self.set(dst, packet.src, self.dt.get(packet.src, packet.src) +
                     packet.get_distance(dst))
    
    def set(self, dst, via, dist):
        changes = self.dt.set(dst, via, dist)
        if changes:
            self.update_list.append(dst)

        return changes

    def send_update(self, packet, port=[], flood=False):
        exclude_ports = port

        routing_update = RoutingUpdate()
        for dst in self.update_list:
            routing_update.add_destination(dst, self.dt.get(dst))

        # exclude sending updates to HostEntites
        for dst in self.port_table.keys():
            if type(dst) == HostEntity:
                exclude_ports.append(self.port_table.get_port(dst))

        self.send(packet, exclude_ports, flood=False)

