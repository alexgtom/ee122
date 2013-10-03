import unittest

from rip_router import DistanceTable, RIPRouter
from sim.basics import BasicHost, DiscoveryPacket, Ping, RoutingUpdate
from hub import Hub

class DistanceTableTestCase(unittest.TestCase):
    def setUp(self):
        self.dt = DistanceTable()

    def testGetAndSet(self):  ## test method names begin 'test*'
        self.dt.set("A", "B", 2)
        self.dt.set("A", "C", 1)
        self.assertEquals(1, self.dt.get("A"))
        self.assertEquals(1, self.dt.get("A", "C"))
        self.assertEquals(2, self.dt.get("A", "B"))

        # get invalid destination
        self.assertEquals(DistanceTable.INFINITY, self.dt.get("D"))

        # get_via
        self.assertEquals("C", self.dt.get_via("A"))

    def testIn(self):
        self.assertFalse("A" in self.dt)
        self.dt.set("A", "B", 2)
        self.assertTrue("A" in self.dt)


def createRIPRouterMock(send_assert=None, handle_rx_assert=None):
    class RIPRouterMock(RIPRouter):
        def send(self, packet, port=None, flood=False):
            if send_assert is not None:
                send_assert(packet, port, flood)
            else:
                super(RIPRouterMock, self).send(packet, port, flood)

        def handle_rx(self, packet, port):
            if handle_rx_assert is not None:
                handle_rx_assert(packet, port)
            else:
                super(RIPRouterMock, self).handle_rx(packet, port)
    return RIPRouterMock


def createBasicHostMock(send_assert=None, handle_rx_assert=None):
    class BasicHostMock(BasicHost):
        def send(self, packet, port=None, flood=False):
            if send_assert is not None:
                send_assert(packet, port, flood)
            else:
                super(BasicHostMock, self).send(packet, port, flood)

        def handle_rx(self, packet, port):
            if handle_rx_assert is not None:
                handle_rx_assert(packet, port)
            else:
                super(BasicHostMock, self).handle_rx(packet, port)
    return BasicHostMock 


class RIPRouterBasicTest(unittest.TestCase):
    """
    Network:
        s1 -- s2
         |     |
        h1    h2
    """
    def setUp(self):
        self.h1 = BasicHost.create('h1')
        self.h2 = BasicHost.create('h2')

        self.s1 = RIPRouter.create('s1')
        self.s2 = RIPRouter.create('s2')

        # connect switches to host
        self.s1.linkTo(self.h1)
        self.s2.linkTo(self.h2)
        
        # connect switches together
        self.s1.linkTo(self.s2)

        dp_h1 = DiscoveryPacket(self.h1, 1)
        dp_h2 = DiscoveryPacket(self.h2, 1)
        dp_s1 = DiscoveryPacket(self.s1, 1)
        dp_s2 = DiscoveryPacket(self.s2, 1)
        
        # send discovery packet between h1 -- s1 on port 0
        self.h1.handle_rx(dp_s1, 0)
        self.s1.handle_rx(dp_h1, 0)

        # send discovery packet between h2 -- s2 on port 0
        self.h2.handle_rx(dp_s2, 0)
        self.s2.handle_rx(dp_h2, 0)

        # send discovery packet between s1 -- s2 on port 1
        self.s1.handle_rx(dp_s2, 1)
        self.s2.handle_rx(dp_s1, 1)

        self.entities = [self.h1, self.h2, self.s1, self.s2]

    def tearDown(self):
        for entity in self.entities:
            entity.remove()

    def testSetUp(self):
        # test setup
        self.assertEquals(1, self.s1.dt.get(self.h1))
        self.assertEquals(1, self.s1.dt.get(self.s2))
        self.assertEquals(1, self.s1.dt.get(self.h1, via=self.h1))
        self.assertEquals(1, self.s1.dt.get(self.s2, via=self.s2))
        self.assertEquals(2, len(self.s1.dt))

        self.assertEquals(1, self.s2.dt.get(self.h2))
        self.assertEquals(1, self.s2.dt.get(self.s1))
        self.assertEquals(1, self.s2.dt.get(self.h2, via=self.h2))
        self.assertEquals(1, self.s2.dt.get(self.s1, via=self.s1))
        self.assertEquals(2, len(self.s2.dt))
        
        self.h1.ping(self.h2)

    def testHandleRoutingUpdate(self):
        # s2 sends routing update to s1
        routing_update = RoutingUpdate()
        for dst in self.s2.dt.keys():
            routing_update.add_destination(dst, self.s2.dt.get(dst))
        self.s1.handle_rx(routing_update, 1)
        
        # assert distance table is updated
        self.assertEquals(1, self.s1.dt.get(self.h1))
        self.assertEquals(1, self.s1.dt.get(self.s2))
        self.assertEquals(2, self.s1.dt.get(self.h2))
        self.assertEquals(3, len(self.s1.dt))

if __name__ == '__main__':
    unittest.main()
