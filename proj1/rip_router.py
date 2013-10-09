from sim.api import *
from sim.basics import *

class DistanceTable(object):
    INFINITY = 100

    def __init__(self):
        self.distance = {}

    def set(self, dst, via, distance):
        if self.distance.get(dst) == None:
            self.distance[dst] = {}
        if distance >= self.INFINITY:
            self.distance[dst][via] = self.INFINITY
        else:
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
        print "packet.src not in self.dt == " + str(packet.src not in self.dt)

        if packet.is_link_up:
            self.port_table.set(packet.src, port)
        else:
            self.port_table.del_host(packet.src)

        if packet.src not in self.dt:
            if packet.is_link_up:
                self.dt.set(packet.src, packet.src, 1)
                self.send_discovery_update(port)
            else:
                # distance table dosent change
                pass
        else:
            if packet.is_link_up:
                self.dt.set(packet.src, packet.src, 1)
                self.send_discovery_update(port)
            else:
                for dst in self.dt.keys():
                    if self.dt.has_via(dst, packet.src):
                        self.dt.set(dst, packet.src, DistanceTable.INFINITY)

    def send_discovery_update(self, port=None):
        if port:
            exclude_ports = [port]
        else:
            exclude_ports = []

        neighbors = self.port_table.keys()
        
        for n in neighbors:
            routing_update = RoutingUpdate()
            for dst in self.dt.keys():
                if dst != n:
                    if self.dt.get_via(n) == n:
                        min_dist = DistanceTable.INFINITY
                    else:
                        min_dist = self.dt.get(dst)
                    routing_update.add_destination(dst, min_dist)
            port = self.port_table.get_port(n) 
            if port not in exclude_ports and self.dt.get_num_via(n) > 1:
                self.send(routing_update, port)

    def handle_routing_update(self, packet, port, send):
        print "handle_routing_update"
        routing_update = RoutingUpdate()

        for dst in packet.all_dests():
            if dst == self:
                # dont add dst to distance table if its self
                continue

            # calculate new distance
            if packet.get_distance(dst) < DistanceTable.INFINITY:
                packet_src = self.port_table.get_host(port)
                new_dist = self.dt.get(packet_src) + packet.get_distance(dst)
            
                # add to routing update if the new_dist is better than the current one
                if new_dist < self.dt.get(dst):
                    routing_update.add_destination(dst, new_dist)

                # set new distance
                self.dt.set(dst, packet_src, new_dist)
            

        if len(routing_update.all_dests()) > 0:
            send(routing_update, port, flood=True)
