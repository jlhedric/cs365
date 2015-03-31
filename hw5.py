#!/usr/bin/env python3
"""
Author: Jade Hedrick
HW5 CS365 Forensics, Spring 2015
"""
import sys
from struct import unpack

MFT_ENTRY_SIZE = 1024
DATA_ATTRIB_ID = 128

class istat:

    def __init__(self, entry_number, image_name):
        self.image_name = image_name
        self.entry_number = int(entry_number)
        self.fd = self.open_file()
        
    def open_file(self):
        """ 
        Author: Brian Levine
        Opens image_name, and calls usage() on error.
        Returns:
          an open file descriptor
        """

        try:
            return(open(self.image_name, "rb"))
        except IOError as err:
            print("IOError opening file: \n\t%s" % err)
            usage()
        except:
            print("Unexpected error:", sys.exc_info()[0])
            usage()

    def find_MFT(self):
        """
        Examine the image's boot sector to parse sector size, cluster size, and the 
        location of the MFT in bytes relative to the start of the image.
        """
        try:
            self.fd.read(11)    #skip 0 thru 10
            bytes_per_sector = unpack("<H", self.fd.read(2))[0]        #bytes 11-12
            sectors_per_cluster = unpack("<B", self.fd.read(1))[0]    #byte 13
            self.fd.read(34)    #skip 14 thru 47
            MFT_start_in_clusters = unpack("<q", self.fd.read(8))[0]    #bytes 48-55
            bytes_per_cluster = bytes_per_sector * sectors_per_cluster
            MFT_start_in_bytes = bytes_per_cluster * MFT_start_in_clusters
            self.fd.seek(MFT_start_in_bytes)    #navigate to start of $MFT
        except:
            print("Unexpected error while reading boot sector:", sys.exc_info()[0])
            sys.exit()
        self.find_entry(MFT_start_in_bytes)

    def find_entry(self, MFT_start_in_bytes):
        """
        At this point we are at entry 0, which is the MFT itself.
        
        """
        MFT_start_in_bytes = MFT_start_in_bytes
        
        MFT_entry = bytearray(self.fd.read(MFT_ENTRY_SIZE))
        
        self.fd.seek(MFT_start_in_bytes)
        self.fd.read(4) #skip bytes 0-3
        fixup_offset = unpack("<H", self.fd.read(2))[0]            #bytes 4-5
        fixup_num_entries = unpack("<H", self.fd.read(2))[0]        #bytes 6-7
        self.fd.read(12) #skip bytes 8-19
        first_attr_offset = unpack("<H", self.fd.read(2))[0]    #bytes 20-21
        self.fd.read(2) #skip bytes 22-23
        used_entry_size = unpack("<L", self.fd.read(4))[0]        #bytes 24-27
        
        #handles fixups
        #TODO: make it less hard coded?
        MFT_entry[510] = MFT_entry[fixup_offset+3]
        MFT_entry[511] = MFT_entry[fixup_offset+4]
        MFT_entry[1022] = MFT_entry[fixup_offset+5]
        MFT_entry[1023] = MFT_entry[fixup_offset+6]
        
        

def usage():
    """
    Catches error when arguments are not valid
    """
    print("Error: \n")
    print("Usage: hw5.py entry_number image_name")

def main():    
    """
    Reads in entry_number and image_name arguments.
    """
    if len(sys.argv) == 3:
        try:
            entry_number = sys.argv[1]
            image_name = sys.argv[2]
        except:
            print("Unexpected error while reading arguments:", sys.exc_info()[0])
            sys.exit()
        #make call to main class
        file = istat(entry_number, image_name)
        file.find_MFT()
    else:
        usage()


if __name__ == '__main__':
    main()