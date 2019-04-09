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

# Payload to encrypt
DATA = "Hello world Hello world Hello world " # CAUTION : The size of the message matters
NB_FRAGS = 3
DATA_SIZE = len(DATA)

# FRAGMENTATION PART
A_THIRD_OF_DATA = DATA_SIZE/NB_FRAGS # corresponding to 1/3 of the data
DATA_FRAG1 = DATA[:A_THIRD_OF_DATA] # first part = begin to 1/3
DATA_FRAG2 = DATA[A_THIRD_OF_DATA: 2 * A_THIRD_OF_DATA] # second part = 1/3 to 2/3
DATA_FRAG3 = DATA[2 * A_THIRD_OF_DATA:] # third part = 2/3 to the end
FRAMES = [DATA_FRAG1, DATA_FRAG2, DATA_FRAG3]

# Get the IV from the Wireshark capture
arp = rdpcap('arp.cap')[0]
IV = arp.iv

# initialization of the writer
pcapWriter = PcapWriter("arpNewFrags.cap", append=True, sync=True)

# loop for all the piece of the frame
for i in range(NB_FRAGS):

    # The seed is composed of the IV and the KEY
    seed = IV + KEY

    # Create a ICV (wich is a CRC32 like the documentation https://docs.python.org/2/library/binascii.html#binascii.crc32)
    dataICV = crc32(FRAMES[i])
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

    # set the flag bit for "more fragment" to one if it's not the last part of the frame
    if i != NB_FRAGS - 1 :
        arpNew.FCfield = arpNew.FCfield | 0x04 # 0x04 is the bit for more fragment (0100)

    arpNew.SC = i # update the value
    pcapWriter.write(arpNew) # write the part of the frame
