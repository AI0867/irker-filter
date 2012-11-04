#!/usr/bin/python

import json
import signal
import socket
import SocketServer
import threading
import Queue

# Find our public-facing IP
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(('8.8.8.8', 80));
HOST = s.getsockname()[0]
s.close()

# These shouldn't need to be changed
LOCALHOST = "127.0.0.1"
PORT = 6659

if __name__ == "__main__":
    packet_queue = Queue.Queue()

    def do_filter(packet, peer):
        print "Got message {0} from peer {1}:{2}".format(packet,peer[0],peer[1])
        if "BANNED" in json.loads(packet)["privmsg"]:
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
    class IrkerConn:
        def __init__(self, target):
            self.target = target
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        def send(self, packet):
            self.sock.sendto(packet, self.target)
        def serve_forever(self):
            while True:
                packet, peer = packet_queue.get()
                if do_filter(packet, peer):
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
