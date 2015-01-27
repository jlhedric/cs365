#!/usr/bin/env python3

#This program adds one space between the columns/hex values

import sys
import math

def printASCII(bytes):
	"""
	Calculates and prints out the ASCII values of the byte line
	"""
	try:
		for b in bytes:
			if b in range(32,127):
				#ASCII value of byte
				print(chr(b), end = "")
			else:
				print(".")

	except:
		print("Error", sys.exc_info()[0])
		sys.exit()

def printHex(bytes):
	"""
	Calculates and prints out the hex values of the byte line
	"""
	try:
		for b in bytes:
			#hex value of byte
			print("%02X" % b, end = " ")
		#if the last "line" isn't 16 bytes, we fill in with spaces
		#to align the first | character
		for num in range(0, 16 - len(bytes)):
			print("   ", end = "")	
		print("|", end = "")

	except:
		print("Error", sys.exc_info()[0])
		sys.exit()

def dostuff(filename):
	"""
	Opens the file, determines how many 16-byte "lines" it has, 
	and makes various function calls to get the correct output.
	"""
	try:
		hexStart = 0
		fd = open(filename, "rb")
		size = len(fd.read())
		#calculates number of 16-byte "lines" based on size of file
		lineCount = math.ceil(size/16)
		fd = open(filename, "rb")
		#for each "line" of 16 or fewer bytes
		for num in range(0,lineCount):
			#starting byte number in hex
			print("%08X" % hexStart, end = " ")
			hexStart = hexStart + 16
			bytes = fd.read(16)
			printHex(bytes)
			printASCII(bytes)
			print("|")
		print("%08x" % size)
			
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
