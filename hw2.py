#!/usr/bin/env python3
"""
Author: Jade Hedrick
HW2 CS365 Forensics, Spring 2015
"""
import sys

class asciiDump:

	def __init__(self, wordlength, filename):
		self.wordlength = wordlength
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

	def ascii_dump(self):
		"""
		Do things
		"""
		try:
			data = self.fd.read(16)
		except:
			print("Unexpected error while reading file:", sys.exc_info()[0])
			sys.exit()
		while data:
			#do stuff
			for d in data:
				#do stuff

			try:
				data = self.fd.read(16)
			except:
				print("Unexpected error while reading file:", sys.exc_info()[0])
				sys.exit()


def usage():
	"""
	Catches error when arguments are not valid
	"""
	print("Error: /n")
	print("Usage: hw2.py integer filename")

def main():	
	"""
	Reads in word length and filename arguments.
	"""
	if len(sys.argv) == 3:
		try:
			wordlength   = int(sys.argv[1])
			filename = sys.argv[2]
			file = asciiDump(wordlength, filename)
		except:
			print("Unexpected error while reading arguments:", sys.exc_info()[0])
			sys.exit()
	else:
		usage()

if __name__ == '__main__':
	main()
