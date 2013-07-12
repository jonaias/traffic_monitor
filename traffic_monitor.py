#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
#  traffic_monitor.py
#  
#  Copyright 2013  <jonas.jonaias@gmail.com
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are
#  met:
#  
#  * Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above
#    copyright notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
#  * Neither the name of the  nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#  
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#  
  

from scapy.all import *
from collections import Counter
from threading import Timer

cnt = Counter()

def print_status():
    most_traffic = cnt.most_common(5)
    if most_traffic:
        print 'MAC              \tBytes/s'
        for entry in most_traffic:
            #     '00:00:00:00:00:00      NNNNN' 
            print entry[0], '\t', entry[1]
    cnt.clear()
    t = Timer(0.5, print_status)
    t.start()

def sniff_callback(pkt):
    cnt[pkt.addr1]+=pkt.len

def main():
    print_status()
    sniff(prn=sniff_callback, offline="test.pcap")
    return 0

if __name__ == '__main__':
    main()

