#!/usr/bin/env python3

import sys

def dostuff(filename):
	"""
	This function DOES STUFF! :D
	"""
	try:
		fd = open(filename, "rb")
		b = fd.read()
		if b:
			print(b)

		#
		#risky code
		#

	except:
		print("Error", sys.exc_info()[0])
		sys.exit()

def usage():
	"""
	Catches error when arguments are not valid
	"""
	print("Error: /n")
	print("Usage: hw1.py filename")

def main():	
	"""
	Reads in filename argument.
	"""
	if len(sys.argv) == 2:
		filename = sys.argv[1]
		dostuff(filename)
	else:
		usage()









if __name__ == '__main__':
	main()
