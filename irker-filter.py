#!/usr/bin/python

import json
import re
import signal
import socket
import SocketServer
import threading
import Queue

DEBUG=0

def debug(message):
    import sys
    if DEBUG:
        sys.stderr.write(message)

# Find our public-facing IP
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(('8.8.8.8', 80));
HOST = s.getsockname()[0]
s.close()

debug("Listening on IP {0}\n".format(HOST))

# These shouldn't need to be changed
LOCALHOST = "127.0.0.1"
PORT = 6659

FILTER = "filter.json"

# TODO: IPv6
class CIDR(object):
    MAX_BITS = 32
    def __init__(self, str_addr):
        if "/" in str_addr:
            str_addr, bits = str_addr.split("/")
            self.bits = int(bits)
        else:
            self.bits = self.MAX_BITS
        addr_parts = str_addr.split(".")
        assert len(addr_parts) == 4
        addr = 0
        for part in addr_parts:
            addr *= 256
            addr += int(part)
        self.addr = self.mask(addr)
    def mask(self, addr):
        return addr & ((2**self.bits - 1) << (self.MAX_BITS - self.bits))
    def __str__(self):
        return "{0}.{1}.{2}.{3}/{4}".format(
            self.addr / 2**24,
            (self.addr / 2**16) % 256,
            (self.addr / 2**8) % 256,
            self.addr % 256,
            self.bits
        )
    def __contains__(self, other):
        try:
            return self.mask(other.addr) == self.addr
        except:
            return False

if __name__ == "__main__":
    packet_queue = Queue.Queue()

    class Filter(object):
        def __init__(self, filename):
            self.filters = json.load(open(filename, "r"))
        def sane(self, packet):
            if len(packet) != 2:
                return False
            if "to" not in packet:
                return False
            if "privmsg" not in packet:
                return False
            targets = packet["to"]
            if isinstance(targets, basestring):
                return True
            if not isinstance(targets, list):
                return False
            for target in targets:
                if not isinstance(target, basestring):
                    return False
            return True
        def match(self, packet, peer):
            debug("Got message {0} from peer {1}:{2}... ".format(packet,peer[0],peer[1]))
            try:
                packet = json.loads(packet)
            except:
                debug("exception on JSON parse\n")
                return False
            if not self.sane(packet):
                debug("not sane\n")
                return False
            for f in self.filters:
                if self.filter_match(f, packet, peer):
                    debug("OK\n")
                    return True
            debug("rejected\n")
            return False
        def filter_match(self, filt, packet, peer):
            for k,v in filt.items():
                if k == "host":
                    try:
                        hosttuple = socket.gethostbyname_ex(v)
                        if peer[0] not in hosttuple[2]:
                            return False
                    except:
                        return False
                elif k == "ip":
                    if CIDR(peer[0]) not in CIDR(v):
                        return False
                elif k == "to":
                    targets = packet["to"]
                    if not isinstance(targets, list):
                        targets = [targets]
                    for target in targets:
                        if not re.match(v, target):
                            return False
                elif k == "privmsg":
                    if not re.match(v, packet["privmsg"]):
                        return False
            return True
    class UDPHandler(SocketServer.BaseRequestHandler):
        def handle(self):
            data = self.request[0].strip()
            packet_queue.put((data, self.client_address))
    class TCPHandler(SocketServer.StreamRequestHandler):
        def handle(self):
            while True:
                line = self.rfile.readline()
                if not line:
                    break
                packet_queue.put((line, self.request.getpeername()))
    class IrkerConn(object):
        def __init__(self, target):
            self.target = target
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.filterer = Filter(FILTER)
        def send(self, packet):
            self.sock.sendto(packet, self.target)
        def serve_forever(self):
            while True:
                packet, peer = packet_queue.get()
                if self.filterer.match(packet, peer):
                    self.send(packet)

    tcpserver = SocketServer.TCPServer((HOST, PORT), TCPHandler)
    udpserver = SocketServer.UDPServer((HOST, PORT), UDPHandler)
    irkerconn = IrkerConn((LOCALHOST, PORT))
    for server in [tcpserver, udpserver, irkerconn]:
        server = threading.Thread(target=server.serve_forever)
        server.setDaemon(True)
        server.start()
    try:
        signal.pause()
    except KeyboardInterrupt:
        raise SystemExit(1)
