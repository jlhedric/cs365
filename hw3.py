#!/usr/bin/env python3
"""
Author: Jade Hedrick
HW2 CS365 Forensics, Spring 2015
"""
import sys
import string
import os

JPEG_HEADER = b'\xff\xd8' 
JPEG_FOOTER = b'\xff\xd9'
filesize = 0

class exifDump:

	def __init__(self, filename):
		self.filename = filename
		self.fd = self.open_file()

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

	def foo(self):
		"""
		TBD
		"""
		filesize = os.path.getsize(self.filename)
		offset = 0
		print(filesize)
		try:
			data = self.fd.read(2)
		except:
			print("Unexpected error while reading file:", sys.exc_info()[0])
			sys.exit()
		if(data != JPEG_HEADER):
			print("Warning: File is not a JPEG. Program will now exit.")
			sys.exit()
		else:
			print("Hello JPEG.")
		

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
		file.foo()
	else:
		usage()


if __name__ == '__main__':
	main()