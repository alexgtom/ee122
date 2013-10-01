import unittest

from rip_router import DistanceTable

class DistanceTableTestCase(unittest.TestCase):
    def setUp(self):
        self.dt = DistanceTable()
    def testGetAndSet(self):  ## test method names begin 'test*'
        self.dt.set("A", "B", 2)
        self.dt.set("A", "C", 1)
        self.assertEquals(1, self.dt.get("A"))
        self.assertEquals(1, self.dt.get("A", "C"))
        self.assertEquals(2, self.dt.get("A", "B"))

if __name__ == '__main__':
    unittest.main()
