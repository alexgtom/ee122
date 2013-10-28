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
            try: return self.distance[dst][via]
            except KeyError: return self.INFINITY
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
        self.last_sent = {}
        self.update_number = 0
        self.last_update = []

    def handle_rx (self, packet, port, send=None):
        
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
            if packet.dst not in self.dt: return
            dst = self.dt.get_via(packet.dst)
            if self.dt.get(packet.dst) != DistanceTable.INFINITY:
                send(packet, self.port_table.get_port(dst))
            else:
                # drop packet since there no path
                pass

    def handle_discovery_packet(self, packet, port, send):
        if packet.is_link_up:
            self.port_table.set(packet.src, port)
        else:
            self.port_table.del_host(packet.src)
    
        if packet.is_link_up:
            self.set(packet.src, packet.src, 1)
        else:
            self.set(packet.src, packet.src, DistanceTable.INFINITY, force=False)
        self.send_update()


    def handle_routing_update(self, packet, port, send):
        for dst in packet.all_dests():
            self.set(dst, packet.src, self.dt.get(packet.src, packet.src) +
                     packet.get_distance(dst))
        #if self.update_number > 0:
        #    for node in self.last_update:
        #        # if the node from the last update isnt in this update
        #        # an implicit withdrawal happened
        #        if node not in packet.all_dests():
        #            for dst in self.dt.keys():
        #                if self.dt.has_via(dst, node):
        #                    self.set(dst, node, DistanceTable.INFINITY)

        if packet.src in self.last_sent:
            for dst in filter(lambda dst: dst in self.dt and dst not in packet.all_dests(), self.last_sent[packet.src]):
                self.dt.delete(dst)

                [self.dt.set(d, dst, DistanceTable.INFINITY) for d in self.dt.keys() if self.dt.has_via(d, dst)]

        self.send_update()
        
    def set(self, dst, via, dist, force=False):
        changes = self.dt.set(dst, via, dist)
        if changes or force:
            self.update_list.append(dst)

        return changes

    def send_update(self, port=[], flood=True):
        if type(port) != list:
            port = [port]

        neighbor_list = self.port_table.keys()
        
        for neighbor in neighbor_list:
            if isinstance(neighbor, HostEntity):
                # exclude sending updates to HostEntites
                continue
            routing_update = RoutingUpdate()
            if len(self.update_list) > 0:
                nodes = self.dt.keys()
                for dst in nodes:
                    if dst == neighbor:
                        continue
                    # poison reverse
                        
                    if neighbor in self.last_sent and dst in self.last_sent[neighbor] and self.last_sent[neighbor][dst] == self.dt.get(dst): continue
                    else: self.last_sent[neighbor] = {}
                    self.last_sent[neighbor][dst] = self.dt.get(dst)
                    routing_update.add_destination(dst, self.dt.get(dst))
            if len(routing_update.all_dests()) > 0:
                self.send(routing_update, 
                          self.port_table.get_port(neighbor), 
                          flood=False)

