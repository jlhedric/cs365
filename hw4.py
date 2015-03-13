#!/usr/bin/env python3
"""
Author: Jade Hedrick
HW4 CS365 Forensics, Spring 2015
"""
import sys
import math
from struct import unpack

FAT16_ENTRY_SIZE = 32

class fsttat:

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

	def boot_parser(self):
		"""
		Reads the contents of a FAT16 boot sector and prints them out.
		This is the ugliest code I have ever written. :D
		"""
		try:
			self.fd.read(3) #skip bytes 0-2
			OEM_name = bytes.decode(self.fd.read(8)) 
			sec_size = unpack("<H", self.fd.read(2))[0]
			sec_per_clust = unpack("<B", self.fd.read(1))[0]
			reserved_size = unpack("<H", self.fd.read(2))[0] - 1 #to account for the 0 start
			num_FATS = unpack("<B", self.fd.read(1))[0]
			max_root_files = unpack("<H", self.fd.read(2))[0]
			num_secs = unpack("<H", self.fd.read(2))[0] - 1  #to account for the 0 start
			self.fd.read(1) #skip byte 21
			FAT_size = unpack("<H", self.fd.read(2))[0]
			self.fd.read(4) #skip bytes 24-27
			before_part = unpack("<L", self.fd.read(4))[0]
			self.fd.read(7) #skip bytes 32-38
			volume_ID = unpack("<L", self.fd.read(4))[0]
			volume_label = bytes.decode(self.fd.read(11)) 
			file_type_label = bytes.decode(self.fd.read(8))
		except:
			print("Unexpected error while reading boot sector:", sys.exc_info()[0])
			sys.exit()

		root_size = max_root_files*FAT16_ENTRY_SIZE / sec_size - 1 #to account for 0
		FAT0_start = reserved_size+1
		FAT0_end = reserved_size+FAT_size
		FAT1_start = FAT0_end+1
		FAT1_end = FAT0_end+FAT_size
		root_start = FAT1_end+1
		root_end = root_start+root_size
		cluster_size = sec_per_clust*sec_size
		cluster_num = math.floor(num_secs/sec_per_clust)
		cluster_area_start = root_end+1
		cluster_area_end = cluster_num*sec_per_clust-1
		if(cluster_area_end != num_secs):	#if there is slack space
			noncluster_start = cluster_area_end +1
		else:								#otherwise
			noncluster_start = num_secs
		cluster_range_end = (num_secs-(cluster_area_start-2)) /2
		
		print("FILE SYSTEM INFORMATION\n--------------------------------------------")
		print("File System Type: ", end = "")
		print(file_type_label)
		print("\nOEM Name: ", end = "")
		print(OEM_name)
		print("Volume ID: ", end = "")
		print("0x%08x" % volume_ID)
		print("Volume Label (Boot Sector): ", end = "")
		print(volume_label)
		print("\nFile System Type Label: ", end = "")
		print(file_type_label)
		print("\nFile System Layout (in sectors) ")
		print("Total Range: ", end = "")
		print("%d - %d" % (0, num_secs))
		print("Total Range in Image: ", end = "")
		print("%d - %d" % (0, cluster_area_end))
		print("* Reserved:  ", end = "")
		print("%d - %d" % (0, reserved_size))
		print("** Boot Sector: ", end = "")
		print(0)
		print("* FAT 0: ", end = "")
		print("%d - %d" % (FAT0_start, FAT0_end))
		print("* FAT 1: ", end = "")
		print("%d - %d" % (FAT1_start, FAT1_end))
		print("Data Area: ", end = "")
		print("%d - %d" % (root_start, num_secs))
		print("** Root Directory: ", end = "")
		print("%d - %d" % (root_start, root_end))
		print("Cluster Area: ", end = "")
		print("%d - %d" % (root_end+1, cluster_area_end))
		print("Non-clustered: ", end = "")
		print("%d - %d" % (noncluster_start, num_secs))
		print("\nCONTENT INFORMATION\n--------------------------------------------")
		print("Sector Size: ", end = "")
		print("%d bytes" % sec_size)
		print("Cluster Size: ", end = "")
		print("%d bytes" % cluster_size)
		print("Total Cluster Range: ", end = "")
		print("%d - %d" % (2, cluster_range_end))

def usage():
	"""
	Catches error when arguments are not valid
	"""
	print("Error: \n")
	print("Usage: hw4.py offset image_name")

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
		file = fsttat(offset, image_name)
		file.boot_parser()
	else:
		usage()


if __name__ == '__main__':
	main()