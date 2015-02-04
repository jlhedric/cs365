#!/usr/bin/env python3
"""
Author: Jade Hedrick
HW2 CS365 Forensics, Spring 2015
"""
import sys

class wordDump:

	def __init__(self, minLength, filename):
		self.minLength = minLength
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

	def word_dump(self):
		"""
		Prints the ascii/unicode with the minimum word length or higher
		"""
		currLength = 0
		word = ""
		#this will be used to keep track of the previous byte
		lastPrintable = False

		try:
			data = self.fd.read(16)
		except:
			print("Unexpected error while reading file:", sys.exc_info()[0])
			sys.exit()
		while data:
			for d in data:
				#while not long enough to be a word
				if(currLength < self.minLength):
					#if printable or new line
					if ((d > 31 and d < 127) or (d == 10)):
						word += chr(d)
						if d != 10:
							lastPrintable = True
							currLength += 1
						#if new line, this kills the premature word
						else:
							lastPrintable = False
							currLength = 0
							word  = ""
					#if we encounter a null character
					elif (d == 0):
						#if consecutive unprintable character
						if(lastPrintable == False):
							#then this is not a unicode byte pair
							#premature word dies
							currLength = 0
							word  = ""
						#else it might be part of unicode byte pair
						else:
							lastPrintable = False
					#else unprintable, kills premature word
					else:
						lastPrintable = False
						currLength = 0
						word  = ""
				#if printable and a whole word
				elif (d > 31 and d < 127):
					lastPrintable = True
					word += chr(d)
					currLength += 1
				#if something else and a whole word
				else:
					#if new line, print word and reset values
					if d == 10:
						lastPrintable = False
						word += chr(d)
						print(word)
						currLength = 0
						word = ""
					#if null value
					elif d == 0:
						#if consecutive unprintable character
						if(lastPrintable == False):
							#then this is not a unicode byte pair
							#print word and reset values
							lastPrintable = False
							print(word)
							currLength = 0
							word = ""
						#else it might be part of unicode byte pair
						else:
							lastPrintable = False
					#if unprintable, print word and reset values
					else:
						lastPrintable = False
						print(word)
						currLength = 0
						word = ""
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
			minLength   = int(sys.argv[1])
			filename = sys.argv[2]
		except:
			print("Unexpected error while reading arguments:", sys.exc_info()[0])
			sys.exit()
		file = wordDump(minLength, filename)
		file.word_dump()
	else:
		usage()

if __name__ == '__main__':
	main()
