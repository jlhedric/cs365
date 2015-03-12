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


	def foo(self):
		"""
		testing
		"""
		print(self.offset)
		print(self.image_name)



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