#!/usr/bin/env python3
"""
Author: Jade Hedrick
HW4 CS365 Forensics, Spring 2015
"""
import sys
from struct import unpack


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

	def foo(self):
		"""
		testing
		"""
		



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
		file.foo()
	else:
		usage()


if __name__ == '__main__':
	main()