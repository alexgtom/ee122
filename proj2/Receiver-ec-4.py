import socket
import getopt
import sys
import time
import os

import Checksum
import BasicSender
class Connection():
    def __init__(self,host,port,start_seq,debug=False):
        self.debug = debug
        self.updated = time.time()
        self.current_seqno = start_seq - 1 # expect to ack from the start_seqno
        self.host = host
        self.port = port
        self.max_buf_size = 5
        self.outfile = open("%s.%d" % (host,port),"w")
        self.seqnums = {} # enforce single instance of each seqno

    def ack(self,seqno, data):
        res_data = []
        self.updated = time.time()
        if seqno > self.current_seqno and seqno <= self.current_seqno + self.max_buf_size:
            self.seqnums[seqno] = data
            for n in sorted(self.seqnums.keys()):
                if n == self.current_seqno + 1:
                    self.current_seqno += 1
                    res_data.append(self.seqnums[n])
                    del self.seqnums[n]
                else:
                    break # when we find out of order seqno, quit and move on

        if self.debug:
            print "next seqno should be %d" % (self.current_seqno+1)

        # note: we return the /next/ sequence number we're expecting
        return self.current_seqno+1, res_data

    def record(self,data):
        self.outfile.write(data)
        self.outfile.flush()

    def end(self):
        self.outfile.close()

class Receiver():
    PACKET_SIZE = 1472
    CHUNK_SIZE = PACKET_SIZE - 5 - 10 - 10 - 3 

    def __init__(self, dest, port, filename, listenport=33122,debug=False,timeout=10):
        super(Sender, self).__init__(dest, port, filename, debug)
        self.filename = filename
        self.window = Window()
        self.current_seqno = 0
        self.debug = debug
        self.timeout = timeout
        self.last_cleanup = time.time()
        self.port = listenport
        self.host = ''
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.settimeout(timeout)
        self.s.bind((self.host,self.port))
        self.connections = {} # schema is {(address, port) : Connection}
        self.MESSAGE_HANDLER = {
            'start' : self._handle_start,
            'data' : self._handle_data,
            'end' : self._handle_end,
            'ack' : self._handle_ack
        }
        self.done = False

    # Main sending loop.
    def start(self):
        print "===== Welcome to Bears-TP Receiver v1.3! ====="
        print "* Listening on port %d..." % self.port
        self.start_time = time.time()
        msg_type = None
        received_msg_type = None
        sent_msg_type = None
        while not self.done:
            try:
                while not self.window.is_full() and sent_msg_type != 'end':
                    sent_msg_type, seqno, packet = self.send_window()

                message, address = self.receive(0.5)
                if message == None:
                    self.handle_timeout()
                else:
                    msg_type, seqno, data, checksum = self.split_packet(message)

                try:
                    seqno = int(seqno)
                except:
                    raise ValueError
                if self.debug:
                    print "%s %d %s %s" % (msg_type, seqno, data, checksum)

                if Checksum.validate_checksum(message):
                    if msg_type == 'start' or msg_type == 'data' or msg_type =='end':
                        #Do receiver functions
                        received_msg_type = msg_type
                        self.MESSAGE_HANDLER.get(received_msg_type,self._handle_other)(seqno, data, address)
                    elif msg_type == 'ack':
                        self.handle_ack(seqno)

                elif self.debug:
                    print "checksum failed: %s" % message
            except (KeyboardInterrupt, SystemExit):
                exit()
            except ValueError, e:
                if self.debug:
                    print e
                pass # ignore


            if len(self.window) == 0 && received_msg_type == 'end':
                self.done = True

        self.infile.close()
        self.end_time = time.time()
        if self.debug:
            self.print_statistics()

    def handle_timeout(self):
        for seqno in self.window.packets_dict:
            self.resend(seqno)

    def handle_ack(self, ack):
        if ack not in self.window.ack_count:
            self.window.ack_count[ack] = 0
            self.handle_new_ack(ack)
        else:
            self.window.ack_count[ack] += 1
            if self.window.ack_count[ack] == 3:
                self.handle_dup_ack(ack)

    def handle_new_ack(self, ack):
        for seqno in self.window.packets_dict.keys():
            if seqno < ack:
                self.window.remove(seqno)
        if not self.window.is_full():
            msg_type, seqno, packet = self.send_window()
            if msg_type == 'end':
                self.done = True

    def handle_dup_ack(self, ack):
        self.resend(ack)

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

    def send_window(self):
        data = self.get_file_chunk()

        if self.current_seqno == 0:
            msg_type = 'start'
        elif data == None:
            msg_type = 'end'
            data = ""
        else:
            msg_type = 'data'

        seqno = self.current_seqno
        self.current_seqno += 1
        
        # create packet
        packet = self.make_packet(msg_type, seqno, data)
        assert len(packet) <= self.PACKET_SIZE

        # add to window
        self.window.set(seqno, packet)

        # send packet
        super(Sender, self).send(packet)

        return (msg_type, seqno, packet)

    def print_statistics(self):
        file_size = os.path.getsize(self.filename)
        total_time = self.end_time - self.start_time
        print ("Transmission Statistics:")
        print ("-----------------------------------")
        print ("File size: %d" % file_size)
        print ("Number of packets sent: %d" % (self.current_seqno-1))
        print ("Elapsed time: %f seconds" % total_time)
        print ("Throughput: " +  str(file_size/total_time) + " bps")
        print ("-----------------------------------")


    # sends a message to the specified address. Addresses are in the format:
    #   (IP address, port number)
    def send_ack_packet(self, message, address):
        self.s.sendto(message, address)

    # this sends an ack message to address with specified seqno
    def _send_ack(self, seqno, address):
        m = "ack|%d|" % seqno
        checksum = Checksum.generate_checksum(m)
        message = "%s%s" % (m, checksum)
        self.send_ack_packet(message, address)

    def _handle_start(self, seqno, data, address):
        if not address in self.connections:
            self.connections[address] = Connection(address[0],address[1],seqno,self.debug)
            if self.debug:
                print "Accepted new connection %s" % str(address)
        self._handle_data(seqno, data, address)

    # ignore packets from uninitiated connections
    def _handle_data(self, seqno, data, address):
        if address in self.connections:
            conn = self.connections[address]
            ackno,res_data = conn.ack(seqno,data)
            for l in res_data:
                if self.debug:
                    print l
                conn.record(l)
            self._send_ack(ackno, address)

    # handle end packets
    def _handle_end(self, seqno, data, address):
        self._handle_data(seqno, data, address)
        # Do not actually terminate connection, since Sender does not send ACKs to FINACKs

    # I'll do the ack-ing here, buddy
    def _handle_ack(self, seqno, data, address):
        pass

    # handler for packets with unrecognized type
    def _handle_other(self, seqno, data, address):
        pass

    def _split_message(self, message):
        pieces = message.split('|')
        msg_type, seqno = pieces[0:2] # first two elements always treated as msg type and seqno
        checksum = pieces[-1] # last is always treated as checksum
        data = '|'.join(pieces[2:-1]) # everything in between is considered data
        return msg_type, seqno, data, checksum

    def _cleanup(self):
        if self.debug:
            print "clean up time"
        now = time.time()
        for address in self.connections.keys():
            conn = self.connections[address]
            if now - conn.updated > self.timeout:
                if self.debug:
                    print "killed connection to %s (%.2f old)" % (address, now - conn.updated)
                conn.end()
                del self.connections[address]
        self.last_cleanup = now

if __name__ == "__main__":
    def usage():
        print "BEARS-TP Receiver"
        print "-p PORT | --port=PORT The listen port, defaults to 33122"
        print "-t TIMEOUT | --timeout=TIMEOUT Receiver timeout in seconds"
        print "-d | --debug Print debug messages"
        print "-h | --help Print this usage message"

    try:
        opts, args = getopt.getopt(sys.argv[1:],
                               "p:dt:", ["port=", "debug=", "timeout="])
    except:
        usage()
        exit()

    port = 33122
    debug = False
    timeout = 10

    for o,a in opts:
        if o in ("-p", "--port="):
            port = int(a)
        elif o in ("-t", "--timeout="):
            timeout = int(a)
        elif o in ("-d", "--debug="):
            debug = True
        else:
            print usage()
            exit()
    r = Receiver(port, debug, timeout)
    r.start()
