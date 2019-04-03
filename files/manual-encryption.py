#!/usr/bin/env python

""" Manually decrypt a wep message given the WEP key"""

__author__      = "Labinot Rashiti & Dylan Hamel"
__copyright__   = "Copyright 2019, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "labinot.rashiti@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from binascii import *
import rc4

#Cle wep AA:AA:AA:AA:AA
# Warning : \x means that the next value is in hexadecimal
KEY ='\xaa\xaa\xaa\xaa\xaa'

# Get the IV from the Wireshark capture
arp = rdpcap('arp.cap')[0]
IV = arp.iv

# Payload to encrypt
DATA = "Hello World Hello World Hello World Hello World Hello World Hello World Hello World Hello World Hello World Hello World" # The actual payload

# The seed is composed of the IV and the KEY
seed = IV + KEY

# Create a ICV (wich is a CRC32 like the documentation https://docs.python.org/2/library/binascii.html#binascii.crc32)
dataICV = crc32(DATA)
dataICV = struct.pack('<i', dataICV)

# Encapsulation of the data with the ICV
dataWithICV = DATA + dataICV

# Generate the encrypted output
encryptedDataWithICV = rc4.rc4crypt(dataWithICV, seed)

# Get the encrypted ICV from the output and format it to as a Long type
encryptedICV = encryptedDataWithICV[-4:]
(encryptedICVLong,) = struct.unpack('!L', encryptedICV)

# Get the encrypted Data from the output
encryptedData = encryptedDataWithICV[:-4]

# Forge the frame with the encrypted outputs
arpNew = rdpcap('arp.cap')[0]
arpNew.wepdata = encryptedData
arpNew.icv = encryptedICVLong

#Create the file
wrpcap("arpNew.cap", arpNew)

print("PLAIN DATA in hexadecimal : " + DATA.encode("hex"))
print("ENCRYPTED DATA in hexadecimal : " + arpNew.wepdata.encode("hex"))