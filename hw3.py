#!/usr/bin/env python3
"""
Author: Jade Hedrick
HW3 CS365 Forensics, Spring 2015
"""
import sys
#import string
#import os
from tags import TAGS
from struct import unpack


JPEG_HEADER = b'\xff\xd8'

class exifDump:

	def __init__(self, filename):
		self.filename = filename
		self.fd = self.open_file()
		#self.filesize = os.path.getsize(self.filename)
		self.offset = 2
		self.endian_offset   = 0
		self.marker_location = 0
		self.marker_value 	 = 0
		self.marker_length 	 = 0

	def open_file(self):
	    """ 
	    Author: Brian Levine
	    Opens filename, and calls usage() on error.
	    Returns:
	      an open file descriptor
	    """

	    try:
	      return(open(self.filename, "rb"))
	    except IOError as err:
	      print("IOError opening file: \n\t%s" % err)
	      usage()
	    except:
	      print("Unexpected error:", sys.exc_info()[0])
	      usage()

	def check_jpeg(self):
		"""
		Checks that the file is a JPEG. If it isn't, exits. 
		Else, continues to find markers.
		"""
		try:
			data = self.fd.read(2)
		except:
			print("Unexpected error while reading file:", sys.exc_info()[0])
			sys.exit()
		#if not JPEG	
		if(data != JPEG_HEADER):
			print("Warning: File is not a JPEG. Program will now exit.")
			sys.exit()
		else:
			self.find_markers()

	def find_markers(self):
		"""
		Cycles through the metadata of the JPEG. Makes call to check_exif_and_endian()
		for each marker. 
		"""
		#run until FFDA marker
		while self.marker_value != int.from_bytes(b'\xFF\xDA', byteorder='big'):
			self.marker_location = self.fd.tell()
			try:
				self.marker_value = unpack(">H", self.fd.read(2))[0]
				self.marker_length = unpack(">H", self.fd.read(2))[0]
			except:
				print("Unexpected error while reading markers:", sys.exc_info()[0])
			print("[0x%04X]" % self.marker_location, end = " ")
			print("Marker 0x%04X" % self.marker_value, end = " ")
			print("size=0x%04X" % self.marker_length)
			self.check_exif_and_endian()
			self.offset = self.marker_location + 2 + self.marker_length
			self.fd.seek(self.offset)

	def check_exif_and_endian(self):
		"""
		Reads in first 6 bytes of marker headers. If exif, checks next 2 bytes for 
		endianness. If big endian, make call to get_IFD(), otherwise exit.
		"""	
		try:	
			data = self.fd.read(6)
		except:
			print("Unexpected read error while checking exif:", sys.exc_info()[0])
		#if exif
		if(data == b'Exif\x00\x00'):
			self.endian_offset = self.fd.tell()
			#if big endian
			if(self.fd.read(2) == b'MM'):
				#skip over 00 2a
				self.fd.read(2)
				self.get_IFD()
			else:
				sys.exit()
	
				

	def get_IFD(self):
		"""
		Prints number of IFD entries.
		"""
		bytes_per_component = (0,1,1,2,4,8,1,1,2,4,8,4,8)
		width = 35
		try:
			self.offset = unpack(">L", self.fd.read(4))[0]
			self.fd.read(self.offset - 8)
			num_entries = unpack(">H", self.fd.read(2))[0]
			print("Number of IFD Entries: ", num_entries)
		except:
			print("Unexpected read error while fetching number of IFD entries:", sys.exc_info()[0])
		#for num_entries
		for num in range(1, num_entries+1):
			tag = unpack(">H", self.fd.read(2))[0]
			print("%X" % tag, end = " ")
			print(TAGS[tag], end = " ")
			format = unpack(">H", self.fd.read(2))[0]
			num_of_components = unpack(">L", self.fd.read(4))[0]
			data_length = bytes_per_component[format]*num_of_components
			if(data_length <= 4):
				entry_data = unpack(">H", self.fd.read(2))[0]





			entry_data = unpack(">L", self.fd.read(4))[0]
			
			#save where we were
			next_tag = self.fd.tell()
			#if tiny data
			if(data_length <= 4):
				print(entry_data)
			else:
				#move back to 0x4d
				self.fd.seek(self.endian_offset)
				#read up to the data offset
				self.fd.read(entry_data)
				print(self.fd.read(data_length).decode("utf-8").rjust(width))
				#go to the next tag
				self.fd.seek(next_tag)



			





		
			
		
			

def usage():
	"""
	Catches error when arguments are not valid
	"""
	print("Error: \n")
	print("Usage: hw3.py filename")

def main():	
	"""
	Reads in filename argument.
	"""
	if len(sys.argv) == 2:
		try:
			filename = sys.argv[1]
		except:
			print("Unexpected error while reading argument:", sys.exc_info()[0])
			sys.exit()
		#make call to main class
		file = exifDump(filename)
		file.check_jpeg()
	else:
		usage()


if __name__ == '__main__':
	main()