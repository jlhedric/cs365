#!/usr/bin/env python3

import sys



def usage():
	"""
	Catches error when arguments are not valid
	"""
	print("Error: /n")
	print("Usage: hw1.py number filename")

def main():	
	"""
	Reads in filename argument.
	"""
	if len(sys.argv) == 3:
		try:
			number   = int(sys.argv[1])
			filename = sys.argv[2]
			#dostuff(filename)
		except:
			print("Unexpected error while reading arguments:", sys.exc_info()[0])
			sys.exit()
	else:
		usage()

if __name__ == '__main__':
	main()
