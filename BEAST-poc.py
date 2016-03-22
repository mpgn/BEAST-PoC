#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
    BEAST attack - PoC
    Implementation of the cryptographic path behind the attack
    Author: mpgn <martial.puygrenier@gmail.com>
'''

import random
import binascii
import sys
from Crypto.Cipher import AES
from Crypto import Random

"""
    AES-CBC
    function encrypt, decrypt, pad, unpad
    You can fix the IV in the function encrypt() because TLS 1.0 fix the IV
    for the second, third... request (to gain time)
"""

def pad(s):
    return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)

def unpad(s):
    return s[:-ord(s[len(s)-1:])]

# we admit the handshake produce a secret key for the session
# of course we do not have any HMAC etc .. but there are not usefull in this attack
def encrypt( msg, iv_p=0):
    raw = pad(msg)
    if iv_p == 0:
        iv = Random.new().read( AES.block_size )
    else:
        iv = iv_p
    global key
    key = Random.new().read( AES.block_size )
    cipher = AES.new('V38lKILOJmtpQMHp', AES.MODE_CBC, iv )
    return cipher.encrypt( raw )

"""
    The PoC of BEAST attack -
    Implementation of the cryptographic path behind the attack
    - the attacker can retrieve the request send be the client 
    - but also make the client send requests with the plain text of his choice
"""

def xor_strings(xs, ys, zs):
    return "".join(chr(ord(x) ^ ord(y) ^ ord(z)) for x, y, z in zip(xs, ys, zs))

def xor_block(vector_init, previous_cipher,p_guess):
    xored = xor_strings(vector_init, previous_cipher, p_guess)
    return xored

def split_len(seq, length):
    return [seq[i:i+length] for i in range(0, len(seq), length)]

# the PoC start here, two method, one with two request
# the other with two request
def run_two_request(find_me):
    print "Start decrypting the request block 0 --> block 0\n"
    
    secret = []

    # the part of the request the atacker know, can be null
    i_know = "flag: "

    # padding is the length we need to add to i_know to create a length of 15 bytes
    padding = 16 - len(i_know) - 1
    i_know = "a"*padding + i_know

    # add_byte will be decrement every byte deciphered
    add_byte = 16
    length_block = 16
    t = 0

    # retrieve all the request
    while(t < (len(find_me)-len("flag: "))):
        for i in range(0,256):
            
            # good pad
            if (add_byte+padding) < 0:
                s = find_me[-1*(add_byte+padding):]
            else:
                s = find_me

            # the client send the encrypted request with socket and TLS1.0
            # you intercept the request and now you have: enc
            enc = encrypt("a"*(add_byte+padding) + s)

            # get the value of the request ciphered
            original = split_len(binascii.hexlify(enc), 32)

            # GUESS XOR VI XOR C_I_1 build by the attacker
            vector_init = str(enc[-length_block:])
            previous_cipher = str(enc[0:length_block])
            p_guess = i_know + chr(i)
         
            xored = xor_block( vector_init, previous_cipher, p_guess)

            # with some javascript injection, you force the client to send
            # request of your choice, the TLS1.0 fix the IV to the last block of the previous request
            # with a MiTM you intercept the result and get
            enc = encrypt(xored, vector_init)

            result = split_len(binascii.hexlify(enc), 32)

            sys.stdout.write("\r%s -> %s " % (original[1], result[0]))
            sys.stdout.flush()

            # if the result request contains the same cipher block from the original request -> OK
            if result[0] == original[1]:
                print " Find char " + chr(i)
                i_know = p_guess[1:]
                add_byte = add_byte - 1
                secret.append(chr(i))
                t = t + 1
                break
            elif i == 255:
                print "Unable to find the char..."
                return secret
    return secret

# the PoC start here        
def run_three_request(find_me):
    print "Start decrypting the request using block 0 --> block 1\n"

    secret = []

    # the part of the request the atacker know, can be null
    i_know = "flag: "

    # padding is the length we need to add to i_know to create a length of 15 bytes
    padding = 16 - len(i_know) - 1
    i_know = "a"*padding + i_know
    length_block = 16
    t = 0

    # retrieve all the request
    while(t < (len(find_me)-len("flag: "))):
        for i in range(0,256):
            # good pad
            if padding < 0:
                s = find_me[-1*(padding):]
            else:
                s = find_me
            
            # the first request is send
            first_r = encrypt("a"*(padding) + s)
            # the second request is send
            enc = encrypt("a"*(padding) + s, first_r[-length_block:])

            # get the value of the request ciphered
            original = split_len(binascii.hexlify(enc), 32)

            # GUESS XOR VI XOR C_I_1 build by the attacker
            vector_init = str(enc[-length_block:])
            previous_cipher = str(first_r[-length_block:])
            p_guess = i_know + chr(i)

            xored = xor_block( vector_init, previous_cipher, p_guess)

            # with some javascript injection, you force the client to send the
            # request of your choice, the TLS1.0 fix the IV to the last block of the previous request
            # with a MiTM you intercept the result and get
            enc = encrypt(xored, vector_init)

            result = split_len(binascii.hexlify(enc), 32)

            sys.stdout.write("\r%s -> %s " % (original[0], result[0]))
            sys.stdout.flush()

            # if the result request contains the same cipher block from the original request -> OK
            if result[0] == original[0]:
                print " Find char " + chr(i)
                i_know = p_guess[1:]
                padding = padding -1
                secret.append(chr(i))
                t = t + 1
                break
            elif i == 255:
                print "Unable to find the char..."
                return secret
    return secret


# the attacker don't know the flag
secret = run_three_request("flag: WIN{TLS_1.0_Not_SO_Good_With_Socket}")
# or
# secret = run_two_request("flag: WIN{TLS_1.0_Not_SO_Good_With_Socket}")

found = ''.join(secret)
print "\n" + found

