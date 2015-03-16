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

	def __init__(self, offset, image_name):
		self.image_name = image_name
		self.offset = offset
		self.fd = self.open_file()
		
	def open_file(self):
	    """ 
	    Author: Brian Levine
	    Opens filename, and calls usage() on error.
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

	#
	## At this point in time you have gotten to the start of the $MFT (we hope)
	## Your next step is to parse the data of Table 13.1
	## Good luck soldier
	#


def usage():
	"""
	Catches error when arguments are not valid
	"""
	print("Error: \n")
	print("Usage: hw5.py offset image_name")

def main():	
	"""
	Reads in offset and image_name arguments.
	"""
	if len(sys.argv) == 3:
		try:
		    offset = sys.argv[1]
		    image_name = sys.argv[2]
		except:
			print("Unexpected error while reading arguments:", sys.exc_info()[0])
			sys.exit()
		#make call to main class
		file = istat(offset, image_name)
		file.find_MFT()
	else:
		usage()


if __name__ == '__main__':
	main()