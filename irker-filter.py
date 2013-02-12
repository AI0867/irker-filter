#!/usr/bin/python

import cidr
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

def find_public_ip(sockettype, addr):
    try:
        s = socket.socket(sockettype, socket.SOCK_DGRAM)
        s.connect((addr, 80))
        host = s.getsockname()[0]
        s.close()
        return host
    except:
        return None

# These shouldn't need to be changed
LOCALHOST = "127.0.0.1"
PORT = 6659

FILTER = "filter.json"


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
                    if not isinstance(v, list):
                        v = [v]
                    peerip = cidr.CIDR(peer[0])
                    matches = [peerip in cidr.CIDR(mask) for mask in v]
                    if not any(matches):
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

    # Find our public-facing IPs
    host_v4 = find_public_ip(socket.AF_INET, '8.8.8.8') # google-public-dns-a.google.com
    host_v6 = find_public_ip(socket.AF_INET6, '2a00:1450:400c:c05::67') # ipv6.google.com

    servers = []
    for host in filter(lambda x:x, [host_v4, host_v6]):
        debug("Listening on {0}\n".format(host))
        servers.append(SocketServer.TCPServer((host, PORT), TCPHandler))
        servers.append(SocketServer.UDPServer((host, PORT), UDPHandler))
    if not servers:
        raise Exception("Not listening on any IPs")
    servers.append(IrkerConn((LOCALHOST, PORT)))
    for server in servers:
        server = threading.Thread(target=server.serve_forever)
        server.setDaemon(True)
        server.start()
    try:
        signal.pause()
    except KeyboardInterrupt:
        raise SystemExit(1)
