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
		Does things
		"""
		count = 0
		word = ""

		try:
			data = self.fd.read(16)
		except:
			print("Unexpected error while reading file:", sys.exc_info()[0])
			sys.exit()
		while data:
			for d in data:
				#while we aren't long enough to be a word
				while(count < wordlength):
					#if printable or new line
					if d > 31 and d < 127 or d == 10:
						word += chr(d)
						if d != 10:
							count +=
						#if new line, this kills the premature word
						else:
							count = 0
							word  = ""
				#if printable
				if d > 31 and d < 127:
					word += chr(d)
					count +=
				else:
					if d == 10:
						word += chr(d)
						print(word)
						count = 0
						word = ""
					else:
						print(word)
						count = 0
						word = ""

				# #if reached minimum word length
				# if (count >= wordlength):
				# 	#and haven't already printed out the word
				# 	if(oldWord == False):
				# 		print(word)
				# 		oldWord = True
				# 	else:
				# 		#print next letter in the word
				# 		print (chr(d))
				# #if not printable or new line
				# if d < 31 and d > 127 and d != 10:
				# 	count = 0
				# 	word = ""
				# 	oldWord = False
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
		except:
			print("Unexpected error while reading arguments:", sys.exc_info()[0])
			sys.exit()
		file = asciiDump(wordlength, filename)
		file.ascii_dump()
	else:
		usage()

if __name__ == '__main__':
	main()
