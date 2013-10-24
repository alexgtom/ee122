from BasicTest import *
from cStringIO import StringIO

#This makes sure we send start and end packets during transer of a tiny file... so small

class StartAndEndTest(BasicTest):
    
    def __init__(self, forwarder, input_file):
        self.forwarder = forwarder
        self.input_file = input_file
        #self.input_file = StringIO("a") #overrides input file passed to it
        self.forwarder.register_test(self, self.input_file)

        self.start_spotted = False
        self.end_spotted = False

    def handle_packet(self):
        for p in self.forwarder.in_queue:
            if p.msg_type == 'start':
                self.start_spotted = True
            if p.msg_type == 'end':
                self.end_spotted = True
            self.forwarder.out_queue.append(p)
        self.forwarder.in_queue = []

    def result(self, receiver_outfile):
        if not os.path.exists(receiver_outfile):
            raise ValueError("No such file %s" % str(receiver_outfile))

        if not self.start_spotted:
            print "Didn't see a start packet"
        if not self.end_spotted:
            print "Didn't see an end packet"
        if self.files_are_the_same(self.input_file, receiver_outfile):
            print "Test passes! %s" % self.__class__.__name__
            return True
        else:
            print "Test fails: original file doesn't match received. :("
            return False
        
