import sys
import getopt
import time
import socket

import Checksum
import BasicSender

'''
This is a skeleton sender class. Create a fantastic transport protocol here.
'''

class Window(object):
    def __init__(self, window_size=5):
        self.window_size = window_size
        self.packets_dict = {}

    def set(self, seqno, packet):
        if len(self.packets_dict) == self.window_size:
            raise Exception("Too many packets in window.")
        else:
            self.packets_dict[seqno] = packet

    def get(self, seqno):
        return self.packets_dict[seqno]

    def remove(self, seqno):
        packet = self.get(seqno)
        del self.packets_dict[seqno]
        return packet

    def __contains__(self, seqno):
        return seqno in self.packets_dict

class Sender(BasicSender.BasicSender):
    # packet size - message type - seqno - checksum - number of seperators
    PACKET_SIZE = 1472
    CHUNK_SIZE = PACKET_SIZE - 5 - 10 - 10 - 3 

    def __init__(self, dest, port, filename, debug=False):
        super(Sender, self).__init__(dest, port, filename, debug)
        self.window = Window()
        self.current_seqno = 0

    # Main sending loop.
    def start(self):
        while True:
            try:
                message, address = self.receive()
                msg_type, seqno, data, checksum = self._split_message(message)
                try:
                    seqno = int(seqno)
                except:
                    raise ValueError
                if debug:
                    print "%s %d %s %s" % (msg_type, seqno, data, checksum)
                if Checksum.validate_checksum(message):
                    self.handle_ack(seqno)
                elif self.debug:
                    print "checksum failed: %s" % message

                if time.time() - self.last_cleanup > self.timeout:
                    self._cleanup()
            except socket.timeout:
                self.handle_timeout()
            except (KeyboardInterrupt, SystemExit):
                exit()
            except ValueError, e:
                if self.debug:
                    print e
                pass # ignore

    def handle_timeout(self):
        pass

    def handle_ack(self, ack):
        pass

    def handle_new_ack(self, ack):
        pass

    def handle_dup_ack(self, ack):
        pass

    def log(self, msg):
        if self.debug:
            print msg

    def get_file_chunk(self):
        """ 
        returns a chunk in the file of size CHUNK_SIZE, returns None
        if there are no more chunks left 
        """
        chunk = self.infile.read(self.CHUNK_SIZE)
        if len(chunk) == 0:
            return None
        return chunk

    def resend(self, seqno, address=None):
        """ Resends a packet based on it's seqno """
        super(Sender, self).send(self.window.get(seqno), address)

    def send_start(self, **kwargs):
        return self.send("start", **kwargs)

    def send_data(self, **kwargs):
        return self.send("data", **kwargs)

    def send_end(self, **kwargs):
        return self.send("end", **kwargs)

    def send(self, msg_type, seqno=None, data=None, address=None):
        if data == None:
            data = self.get_file_chunk()
        if seqno == None:
            seqno = self.current_seqno
            self.current_seqno += 1
        
        # create packet
        packet = self.make_packet(msg_type, seqno, data)
        assert len(self.packet) <= self.PACKET_SIZE

        # add to window
        self.window.set(seqno, packet)

        # send packet
        super(Sender, self).send(packet, address)

        return (seqno, packet)



'''
This will be run if you run this script from the command line. You should not
change any of this; the grader may rely on the behavior here to test your
submission.
'''
if __name__ == "__main__":
    def usage():
        print "BEARS-TP Sender"
        print "-f FILE | --file=FILE The file to transfer; if empty reads from STDIN"
        print "-p PORT | --port=PORT The destination port, defaults to 33122"
        print "-a ADDRESS | --address=ADDRESS The receiver address or hostname, defaults to localhost"
        print "-d | --debug Print debug messages"
        print "-h | --help Print this usage message"

    try:
        opts, args = getopt.getopt(sys.argv[1:],
                               "f:p:a:d", ["file=", "port=", "address=", "debug="])
    except:
        usage()
        exit()

    port = 33122
    dest = "localhost"
    filename = None
    debug = False

    for o,a in opts:
        if o in ("-f", "--file="):
            filename = a
        elif o in ("-p", "--port="):
            port = int(a)
        elif o in ("-a", "--address="):
            dest = a
        elif o in ("-d", "--debug="):
            debug = True

    s = Sender(dest,port,filename,debug)
    try:
        s.start()
    except (KeyboardInterrupt, SystemExit):
        exit()
