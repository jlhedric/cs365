#!/usr/bin/env python3
"""
Author: Jade Hedrick
HW2 CS365 Forensics, Spring 2015
"""
import sys
import string
import os
from struct import unpack

JPEG_HEADER = b'\xff\xd8' 

class exifDump:

	def __init__(self, filename):
		self.filename = filename
		self.fd = self.open_file()
		self.filesize = os.path.getsize(self.filename)
		self.offset = 2
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
		while self.marker_value != int.from_bytes(b'\xFF\xDA', byteorder='big'):
			self.marker_location = self.fd.tell()
			self.marker_value = unpack(">H", self.fd.read(2))[0]
			self.marker_length = unpack(">H", self.fd.read(2))[0]
			print("[0x%04X]" % self.marker_location, end = " ")
			print("Marker 0x%04X" % self.marker_value, end = " ")
			print("size=0x%04X" % self.marker_length)
			self.check_exif_and_endian()
			self.offset = self.marker_location + 2 + self.marker_length
			self.fd.seek(self.offset)


	def check_exif_and_endian(self):
		"""
		Reads in first 6 bytes of marker headers. If exif, checks next 2 bytes for 
		endianness. If the header is not exif, continue find_markers(). If big 
		endian, make call to get_IFD()
		"""		
		data = self.fd.read(6)
		#if exif
		if(data == b'Exif\x00\x00'):
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
		self.offset = unpack(">L", self.fd.read(4))[0]
		self.fd.read(self.offset - 8)
		print("Number of IFD Entries: ", unpack(">H", self.fd.read(2))[0])

		
			
		
			

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