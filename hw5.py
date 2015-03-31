#!/usr/bin/env python3
"""
Author: Jade Hedrick
HW5 CS365 Forensics, Spring 2015
"""
import sys
from struct import unpack

MFT_entry_SIZE = 1024
STANDARD_INFO_ID = 16
FILE_NAME_ID = 48
DATA_ID = 128

class istat:

    def __init__(self, entry_number, image_name):
        self.image_name = image_name
        self.entry_number = int(entry_number)
        self.fd = self.open_file()
        self.MFT_entry = []
        
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
        self.parse_MFT_entry_header(self.fd.tell())

    def parse_MFT_entry_header(self, entry_offset):
        """
        At this point we are at an entry and will parse the entry header.
        
        """
        byte_offset = 0
        attr_count = 0
        attr_id = 0
        data_start = 0
        self.MFT_entry = bytearray(self.fd.read(entry_offset))
        signature = unpack("<L", self.MFT_entry[0:4])[0]
        fixup_offset = unpack("<H", self.MFT_entry[4:6])[0]
        fixup_num_entries = unpack("<H", self.MFT_entry[6:8])[0]
        LSN = unpack("<q", self.MFT_entry[8:16])[0]
        seq_value = unpack("<H", self.MFT_entry[16:18])[0]
        link_count = unpack("<H", self.MFT_entry[18:20])[0]
        first_attr_offset = unpack("<H", self.MFT_entry[20:22])[0]
        flags = unpack("<H", self.MFT_entry[22:24])[0]
        used_entry_size = unpack("<L", self.MFT_entry[24:28])[0]
        allocated_size = unpack("<L", self.MFT_entry[28:32])[0]
        file_ref = unpack("<q", self.MFT_entry[32:40])[0]
        next_id = unpack("<H", self.MFT_entry[40:42])[0]
       
        
       
        #handles fixups
        #TODO: make it less hard coded?
        self.MFT_entry[510] = self.MFT_entry[fixup_offset+2]
        self.MFT_entry[511] = self.MFT_entry[fixup_offset+3]
        self.MFT_entry[1022] = self.MFT_entry[fixup_offset+4]
        self.MFT_entry[1023] = self.MFT_entry[fixup_offset+5]
        
        start_attr = first_attr_offset
        
        #cycle through attributes and parses them
        while((byte_offset < used_entry_size) and (attr_count < next_id)):
            attr_size = unpack("<L", self.MFT_entry[start_attr+4:start_attr+8])[0]
            byte_offset = byte_offset + attr_size
            attr_count = attr_count + 1
            attr_id = unpack("<L", self.MFT_entry[start_attr:start_attr+4])[0]
            if attr_id == STANDARD_INFO_ID:
                self.parse_standard(start_attr)
            if attr_id == FILE_NAME_ID:
                self.parse_file_name( start_attr)
            if attr_id == DATA_ID:
                self.parse_data(start_attr)
            start_attr = start_attr + attr_size     #move on to next attribute
                

    def parse_standard(self, attr_start):
        """
        Parses table 13.5
        """
        self.parse_attribute_header(attr_start)
        size = unpack("<L", self.MFT_entry[attr_start+16:attr_start+20])[0]
        content_offset = unpack("<H", self.MFT_entry[attr_start+20:attr_start+22])[0]
        creation_time = unpack("<q", self.MFT_entry[content_offset:content_offset+8])[0]
        file_alter_time = unpack("<q", self.MFT_entry[content_offset+8:content_offset+16])[0]
        MFT_alter_time = unpack("<q", self.MFT_entry[content_offset+16:content_offset+24])[0]
        
        
    def parse_file_name(self, attr_start):
        """
        Parses table 13.7
        """
        self.parse_attribute_header(attr_start)
        size = unpack("<L", self.MFT_entry[attr_start+16:attr_start+20])[0]
        content_offset = unpack("<H", self.MFT_entry[attr_start+20:attr_start+22])[0]
        
    def parse_data(self, attr_start):
        """
        TBD
        """
        self.parse_attribute_header(attr_start)
        #runlist stuff
        
    def parse_attribute_header(self, attr_start):
        """
        Parses table 13.2
        """
        attr_type = unpack("<L", self.MFT_entry[attr_start:attr_start+4])[0]
        attr_len = unpack("<L", self.MFT_entry[attr_start+4:attr_start+8])[0]
        nonres_flag = unpack("<B", self.MFT_entry[attr_start+8:attr_start+9])[0]
        name_len = unpack("<B", self.MFT_entry[attr_start+9:attr_start+10])[0]
        name_offset = unpack("<H", self.MFT_entry[attr_start+10:attr_start+12])[0]
        flags = unpack("<H", self.MFT_entry[attr_start+12:attr_start+14])[0]
        attr_id = unpack("<H", self.MFT_entry[attr_start+14:attr_start+16])[0]
        print("This should happen three times.") 

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