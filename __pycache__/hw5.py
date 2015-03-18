#!/usr/bin/env python3
"""
Author: Jade Hedrick
HW5 CS365 Forensics, Spring 2015
"""
import sys
import math
from struct import unpack

FAT16_ENTRY_SIZE = 32

class istat:

	def __init__(self, entry_number, image_name):
		self.image_name = image_name
		self.entry_number = entry_number
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
			self.fd.read(11)	#skip 0 thru 10
			bytes_per_sector = unpack("<H", self.fd.read(2))[0]		#bytes 11-12
			sectors_per_cluster = unpack("<B", self.fd.read(1))[0]	#byte 13
			self.fd.read(34)	#skip 14 thru 47
			MFT_start_in_clusters = unpack("<q", self.fd.read(8))[0]	#bytes 48-55
			bytes_per_cluster = bytes_per_sector * sectors_per_cluster
			MFT_start_in_bytes = bytes_per_cluster * MFT_start_in_clusters
			self.fd.seek(MFT_start_in_bytes)	#navigate to start of $MFT
		except:
			print("Unexpected error while reading boot sector:", sys.exc_info()[0])
			sys.exit()
		self.parse_MFT_entry(MFT_start_in_bytes)

	def parse_MFT_entry(self, MFT_start_in_bytes):
		"""
		At this point we are at entry 0, which is the MFT itself. We must parse
		the data from Table 13.1.
		"""
		MFT_start_in_bytes = MFT_start_in_bytes
		try:
			signature = bytes.decode(self.fd.read(4))
			fixup_offset = unpack("<H", self.fd.read(2))[0]	
			fixup_num_entries = unpack("<H", self.fd.read(2))[0]
			logfile_seq_num = unpack("<q", self.fd.read(8))[0]
			seq_val = unpack("<H", self.fd.read(2))[0]	
			link_count = unpack("<H", self.fd.read(2))[0]
			first_attr_offset = unpack("<H", self.fd.read(2))[0]	
			flags = unpack("<H", self.fd.read(2))[0]
			used_entry_size = unpack("<L", self.fd.read(4))[0]
			allocated_entry_size = unpack("<L", self.fd.read(4))[0]
			file_ref_to_base = unpack("<q", self.fd.read(8))[0]
			next_attr_id = unpack("<H", self.fd.read(2))[0]
		except:
			print("Unexpected error while reading MFT entry:", sys.exc_info()[0])
			sys.exit()



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