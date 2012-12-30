#!/usr/bin/env python
#
# Embedded EXE extract - Extract an embedded exe by highlighting its 'MZ' header
# Requires the free 'FileInsight' application from McAfee
#
# Copyright (c) 2012, Mick Grove
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
# IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

import sys
import pefile

offset = getSelectionOffset()
length = getLength() - offset #getSelectionLength()

if (length > 0):
    origdoc = list(getDocument())
    newbuf = list()

    for i in range(0, length):
        j = offset + i
        newbuf.append(chr(ord(origdoc[j])))

    str1 = ''.join(newbuf)
    bValidPE = True #default

    try:
        pe = pefile.PE(data=str1)
    except pefile.PEFormatError:
        print "[*] This is not the beginning of a valid PE file!\n[*] Please highlight the 'MZ' ASCII (or 4D5A hex) that begins a valid PE file and try again."
        bValidPE = False

    if bValidPE:
        largest = 0
        for section in pe.sections:
            addr = section.PointerToRawData + section.SizeOfRawData
            if(addr > largest):
                largest = addr

        file_size = largest

        carvedpe = list()
        print "[+] Size of PE file: (0x%x) %s bytes = %.2f kb" % (file_size , file_size, file_size/1024.0)
        for i in range(0, file_size):
            j = offset + i
            carvedpe.append(chr(ord(origdoc[j])))

        newDocument("New carved file", 1)
        setDocument("".join(carvedpe))

        print "PE file successfully carved!"
