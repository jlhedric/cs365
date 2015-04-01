#!/usr/bin/env python3
"""
Author: Jade Hedrick
HW5 CS365 Forensics, Spring 2015
"""
import sys
from struct import unpack

MFT_ENTRY_SIZE = 1024
STANDARD_INFO_ID = 16
FILE_NAME_ID = 48
DATA_ID = 128

class istat:

    def __init__(self, entry_number, image_name):
        self.image_name = image_name
        self.entry_number = int(entry_number)
        self.fd = self.open_file()
        self.MFT_entry = []
        self.cluster_array = []
        self.isResident = True
        self.isEntry = False
        self.BYTES_PER_SEC = 0
        self.SEC_PER_CLUST = 0
        
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
            self.fd.read(11)
            bytes_per_sector = unpack("<H", self.fd.read(2))[0] 
            self.BYTES_PER_SEC = bytes_per_sector       
            sectors_per_cluster = unpack("<B", self.fd.read(1))[0]
            self.SEC_PER_CLUST = sectors_per_cluster    
            self.fd.read(34)    #skip 14 thru 47
            MFT_start_in_clusters = unpack("<q", self.fd.read(8))[0]
            bytes_per_cluster = bytes_per_sector * sectors_per_cluster
            MFT_start_in_bytes = bytes_per_cluster * MFT_start_in_clusters
            self.fd.seek(MFT_start_in_bytes)
        except:
            print("Unexpected error while reading boot sector:", sys.exc_info()[0])
            sys.exit()
        self.parse_MFT_entry()    #parse entry 0 to get our cluster run array

    def find_entry(self):
        """
        Crunches some numbers in our cluster array to find where our desired entry (remember that?) is.
        """
        try:
            bytes_per_cluster = self.BYTES_PER_SEC*self.SEC_PER_CLUST
            entries_per_cluster = int(bytes_per_cluster/MFT_ENTRY_SIZE)
            native_cluster = self.cluster_array[int(self.entry_number/entries_per_cluster)]
        except:
            print("Whoa there buddy! There aren't that many entries in this image!", sys.exc_info()[0])
            sys.exit()
        try:
            self.fd.seek(native_cluster*bytes_per_cluster)  #navigate to the cluster the entry is in
            self.fd.read(MFT_ENTRY_SIZE*(self.entry_number%entries_per_cluster))    #make the necessary hops along the cluster to reach start of entry
        except:
            print("Unexpected error while searching for the entry:", sys.exc_info()[0])
            sys.exit()
        self.isEntry = True
        self.parse_MFT_entry()

    def parse_MFT_entry(self):
        """
        At this point we are at an arbitrary entry (hi mom!) and will parse the entry header.
        Table 13.1
        """
        byte_offset = 0
        attr_count = 0
        attr_id = 0
        self.MFT_entry = bytearray(self.fd.read(MFT_ENTRY_SIZE))
        
        signature = bytes.decode(bytes(self.MFT_entry[0:4]))
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

        if self.isEntry == True:
            print("We parsed the MFT entry's header! This should only happen once.")
        
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
            if attr_id == STANDARD_INFO_ID and self.isEntry == True:         #we only parse non-DATA attributes in our desired entry
                self.parse_standard(start_attr)
            if attr_id == FILE_NAME_ID and self.isEntry == True:
                self.parse_file_name(start_attr)
            if attr_id == DATA_ID:
                self.parse_data(start_attr)
            start_attr = start_attr + attr_size
                    
    def parse_standard(self, attr_start):
        """
        Parses $STANDARDINFO attribute of the current entry. TODO: Handle the funky times.
        """
        
        self.parse_attribute_header(attr_start)
        
        size = unpack("<L", self.MFT_entry[attr_start+16:attr_start+20])[0]
        
        content_offset = unpack("<H", self.MFT_entry[attr_start+20:attr_start+22])[0]
        content_offset = content_offset + attr_start
        creation_time = unpack("<q", self.MFT_entry[content_offset:content_offset+8])[0]
        file_alter_time = unpack("<q", self.MFT_entry[content_offset+8:content_offset+16])[0]
        MFT_alter_time = unpack("<q", self.MFT_entry[content_offset+16:content_offset+24])[0]
        file_acccess_time = unpack("<q", self.MFT_entry[content_offset+24:content_offset+32])[0]
        flag = unpack("<L", self.MFT_entry[content_offset+32:content_offset+36])[0]

        self.parse_flags(flag)
        
        max_num_vers = unpack("<L", self.MFT_entry[content_offset+36:content_offset+40])[0]
        ver_num = unpack("<L", self.MFT_entry[content_offset+40:content_offset+44])[0]
        class_id = unpack("<L", self.MFT_entry[content_offset+44:content_offset+48])[0]
        owner_id = unpack("<L", self.MFT_entry[content_offset+48:content_offset+52])[0]
        security_id = unpack("<L", self.MFT_entry[content_offset+52:content_offset+56])[0]
        quota_charged = unpack("<q", self.MFT_entry[content_offset+56:content_offset+64])[0]
        update_seq_num = unpack("<q", self.MFT_entry[content_offset+64:content_offset+72])[0]

        print("We parsed the standard info attribute of our desired entry! This should only happen once.")
        
    def parse_file_name(self, attr_start):
        """
        Parses $FILENAME attribute of the current entry. TODO: Handle the funky times.
        """
        self.parse_attribute_header(attr_start)
        size = unpack("<L", self.MFT_entry[attr_start+16:attr_start+20])[0]
        
        content_offset = unpack("<H", self.MFT_entry[attr_start+20:attr_start+22])[0]
        content_offset = content_offset + attr_start
       
        ref_of_parent = unpack("<q", self.MFT_entry[content_offset:content_offset+8])[0]
        creation_time = unpack("<q", self.MFT_entry[content_offset+8:content_offset+16])[0]
        modify_time = unpack("<q", self.MFT_entry[content_offset+16:content_offset+24])[0]
        MFT_mod_time = unpack("<q", self.MFT_entry[content_offset+24:content_offset+32])[0]
        access_time = unpack("<q", self.MFT_entry[content_offset+32:content_offset+40])[0]
        allocated_size = unpack("<q", self.MFT_entry[content_offset+40:content_offset+48])[0]
        real_size = unpack("<q", self.MFT_entry[content_offset+48:content_offset+56])[0]
        flag = unpack("<L", self.MFT_entry[content_offset+56:content_offset+60])[0]
        
        self.parse_flags(flag)
        
        reparse = unpack("<L", self.MFT_entry[content_offset+60:content_offset+64])[0]
        name_len = unpack("<B", self.MFT_entry[content_offset+64:content_offset+65])[0]
        namespace = unpack("<B", self.MFT_entry[content_offset+65:content_offset+66])[0]
        name = bytes.decode(bytes(self.MFT_entry[content_offset+66:content_offset+66+name_len*2])) 

        print("We parsed the filename attribute of our desired entry! This should only happen once.")
        
    def parse_data(self, attr_start):
        """
        Parses $DATA attribute of the current entry. TODO: Handle the funky times. Figure out what to do when data is resident.
        """
        self.parse_attribute_header(attr_start)
        if self.isResident == True:
            size = unpack("<L", self.MFT_entry[attr_start+16:attr_start+20])[0]
            content_offset = unpack("<H", self.MFT_entry[attr_start+20:attr_start+22])[0]
            content_offset = content_offset + attr_start
            
        else:
            start_RL = unpack("<q", self.MFT_entry[attr_start+16:attr_start+24])[0]
            end_RL = unpack("<q", self.MFT_entry[attr_start+24:attr_start+32])[0]
            offset_RL = unpack("<H", self.MFT_entry[attr_start+32:attr_start+34])[0]
            offset_RL = offset_RL + attr_start
            start_RL = start_RL + offset_RL
            end_RL = end_RL + offset_RL
            comp_unit_size = unpack("<H", self.MFT_entry[attr_start+34:attr_start+36])[0]
            unused = unpack("<L", self.MFT_entry[attr_start+36:attr_start+40])[0]
            allocated_size = unpack("<q", self.MFT_entry[attr_start+40:attr_start+48])[0]
            actual_size = unpack("<q", self.MFT_entry[attr_start+48:attr_start+56])[0]
            initialized_size = unpack("<q", self.MFT_entry[attr_start+56:attr_start+64])[0]
            
            #handle runlist. Only need to do this initially with entry 0 to populate the cluster array, skip if we're just parsing other entries.

            if(self.isEntry == False):
                rl_offset = -1     #because reasons
                rl_length = 0
                previous_offset = 0

                while(True):
                    curr_byte = unpack("<B", self.MFT_entry[start_RL+rl_offset+rl_length+1:start_RL+rl_offset+rl_length+2])[0]
                    start_RL = start_RL+rl_offset+rl_length+1
                    rl_offset = curr_byte >> 4  #shifting
                    rl_length = curr_byte & 15  #masking
                    if((rl_offset == 0) & (rl_length == 0)):    #if end of runlist
                        break
                    real_length = self.getSigned(self.MFT_entry[start_RL+1:start_RL+rl_length+1])
                    real_offset = self.getSigned(self.MFT_entry[start_RL+rl_length+1:start_RL+rl_length+rl_offset+1])
                    previous_offset = previous_offset + real_offset
                    for x in range(previous_offset, previous_offset+real_length):   #stick all the cluster runs into an array
                        self.cluster_array.append(x)
                print("We parsed the runlist of the MFT! This should only happen once.")                                 
            else:
                print("We parsed the DATA attribute of our desired entry! This should only happen once.")
      
    def parse_attribute_header(self, attr_start):
        """
        Parses table 13.2
        """
        attr_type = unpack("<L", self.MFT_entry[attr_start:attr_start+4])[0]
        attr_len = unpack("<L", self.MFT_entry[attr_start+4:attr_start+8])[0]
        nonres_flag = unpack("<B", self.MFT_entry[attr_start+8:attr_start+9])[0]
        if(nonres_flag == 1):
            self.isResident = False
        else:
            self.isResident = True
        name_len = unpack("<B", self.MFT_entry[attr_start+9:attr_start+10])[0]
        name_offset = unpack("<H", self.MFT_entry[attr_start+10:attr_start+12])[0]
        flags = unpack("<H", self.MFT_entry[attr_start+12:attr_start+14])[0]
        attr_id = unpack("<H", self.MFT_entry[attr_start+14:attr_start+16])[0]

        if self.isEntry == True:
            print("Print out attribute header stuff. This should happen two or three times.")

    def parse_flags(self, flag):
        """
        Checks for the flags in table 13.6.
        """
        read_only = 1
        hidden = 2
        system = 4
        archive = 32
        device = 64
        normal = 128
        temp = 256
        sparse = 512
        reparse_point = 1024
        compressed = 2048
        offline = 4096
        not_indexed = 8192
        encrypted = 16384
        
        # if(read_only&flag == read_only):
        #     print("Read only")
        # if(hidden&flag == hidden):
        #     print("Hidden")
        # if(system&flag == system):
        #     print("System")
        # if(archive&flag == archive):
        #     print("Archive")
        # if(device&flag == device):
        #     print("Device")
        # if(normal&flag == normal):
        #     print("Normal")
        # if(temp&flag == temp):
        #     print("Temporary")
        # if(sparse&flag == sparse):
        #     print("Sparse")
        # if(reparse_point&flag == reparse_point):
        #     print("Reparse Point")
        # if(compressed&flag == compressed):
        #     print("Compressed")
        # if(offline&flag == offline):
        #     print("Offline")
        # if(not_indexed&flag == not_indexed):
        #     print("Not_indexed")
        # if(encrypted&flag == encrypted):
        #     print("Encrypted")
        
    def getSigned(self, byteArray):
        length = len(byteArray)
        if byteArray[-1] >> 7 == 0:
            return(unpack('<q',byteArray + (8-length)* b'\x00')[0])
        else:
            return(unpack('<q',byteArray + (8-length)* b'\xFF')[0])
    
    def convertTime(self, byteArray):
        print("Okay")

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
        file.find_entry()
    else:
        usage()


if __name__ == '__main__':
    main()