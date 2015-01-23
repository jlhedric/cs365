#!/usr/bin/env python3

import sys

def dostuff():
	"""
	What this does
	"""
	print("We'll get back to you on that...")

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
		print(filename)
	else:
		usage()
	# print("Hello world!")
	# a = 3
	# if(a>4):
	# 	print("foo")
	# else:
	# 	print("bar")




if __name__ == '__main__':
	main()
