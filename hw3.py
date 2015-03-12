<<<<<<< HEAD
#!/usr/bin/env python3
"""
Author: Jade Hedrick
HW3 CS365 Forensics, Spring 2015
"""
import sys
from tags import TAGS
from struct import unpack


JPEG_HEADER = b'\xff\xd8'

class exifDump:

	def __init__(self, filename):
		self.filename = filename
		self.fd = self.open_file()
		self.offset = 2
		self.endian_offset = 0

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

	def check_jpeg(self):
		"""
		Checks that the file is a JPEG. If it isn't, exits. 
		Else, continues to find markers.
		"""
		try:
			data = self.fd.read(2)
		except:
			print("Unexpected error while reading file:", sys.exc_info()[0])
			sys.exit()
		#if not JPEG	
		if(data != JPEG_HEADER):
			print("Warning: File is not a JPEG. Program will now exit.")
			sys.exit()
		else:
			self.find_markers()

	def find_markers(self):
		"""
		Cycles through the metadata of the JPEG. Makes call to check_exif_and_endian()
		for each marker. 
		"""
		marker_value = 0
		marker_location = 0
		marker_length = 0
		#run until FFDA marker
		while marker_value != int.from_bytes(b'\xFF\xDA', byteorder='big'):
			marker_location = self.fd.tell()
			try:
				marker_value = unpack(">H", self.fd.read(2))[0]
				marker_length = unpack(">H", self.fd.read(2))[0]
			except:
				print("Unexpected error while reading markers:", sys.exc_info()[0])
			print("[0x%04X]" % marker_location, end = " ")
			print("Marker 0x%04X" % marker_value, end = " ")
			print("size=0x%04X" % marker_length)
			self.check_exif_and_endian()
			self.offset = marker_location + 2 + marker_length
			self.fd.seek(self.offset)

	def check_exif_and_endian(self):
		"""
		Reads in first 6 bytes of marker headers. If exif, checks next 2 bytes for 
		endianness. If big endian, make call to get_IFD(), otherwise exit.
		"""	
		try:	
			data = self.fd.read(6)
		except:
			print("Unexpected read error while checking exif:", sys.exc_info()[0])
		#if exif
		if(data == b'Exif\x00\x00'):
			self.endian_offset = self.fd.tell()
			#if big endian
			if(self.fd.read(2) == b'MM'):
				#skip over 00 2a
				self.fd.read(2)
				self.get_IFD()
			else:
				print("Get back little endian scum! Program will exit for such insolence!")
				sys.exit()

	def get_IFD(self):
		"""
		Prints number of IFD entries. Parses IFD tags with call to format().
		"""
		bytes_per_component = (0,1,1,2,4,8,1,1,2,4,8,4,8)
		try:
			self.offset = unpack(">L", self.fd.read(4))[0]
			self.fd.read(self.offset - 8)
			num_entries = unpack(">H", self.fd.read(2))[0]
			print("Number of IFD Entries: ", num_entries)
		except:
			print("Unexpected read error while fetching number of IFD entries:", sys.exc_info()[0])
		#for num_entries
		for num in range(0, num_entries):
			#at this point we are at the beginning of an entry
			#here we save an index pointing to the next entry 12 bytes away
			next_tag = self.fd.tell() + 12
			tag = unpack(">H", self.fd.read(2))[0]
			print("%X" % tag, end = " ")
			print(TAGS[tag], end = " ")
			format = unpack(">H", self.fd.read(2))[0]
			num_of_components = unpack(">L", self.fd.read(4))[0]
			length = bytes_per_component[format]*num_of_components
			self.format(format, num_of_components, length)
			#no matter where we got to in format(), we only jump 12 bytes from the start of the loop
			self.fd.seek(next_tag)
			# if(length <= 4):
			# 	#WRONG
			# 	data = unpack(">L", self.fd.read(4))[0]
			# 	print(data)
			# 	#WRONG
			# else:
			# 	data = unpack(">L", self.fd.read(4))[0]
			# 	next_tag = self.fd.tell()
				#move back to 0x4d
				# self.fd.seek(self.endian_offset)
				# #read up to the data offset
				# self.fd.read(data)
				# print(self.fd.read(length).decode("utf-8").rjust(35))
				# #go to the next tag
				# self.fd.seek(next_tag)

	#the part where it stops looking pretty
	def format(self, format, num_of_components, length):
		format = format
		length = length
		numerator   = 1
		denominator = 1
		if(format == 1):
			if(length <= 4):
				data = unpack(">B", self.fd.read(1))[0]
				print(data)
			else:
				data_offset = unpack(">L", self.fd.read(4))[0]
				#move back to 0x4d
				self.fd.seek(self.endian_offset)
				#read up to the data offset
				self.fd.read(data_offset)
				data = unpack(">B", self.fd.read(1))[0]
				print(data)
		elif(format == 2):
			if(length <= 4):
				data = bytes.decode(self.fd.read(1))
				print(data)
			else:
				data_offset = unpack(">L", self.fd.read(4))[0]
				#move back to 0x4d
				self.fd.seek(self.endian_offset)
				#read up to the data offset
				self.fd.read(data_offset)
				data = bytes.decode(self.fd.read(length))
				print(data)
		elif(format == 3):
			if(length <= 4):
				data = unpack(">%dH" % num_of_components, self.fd.read(length))[0]
				print(data)
			else:
				data_offset = unpack(">L", self.fd.read(4))[0]
				#move back to 0x4d
				self.fd.seek(self.endian_offset)
				#read up to the data offset
				self.fd.read(data_offset)
				data = unpack(">%dH" % num_of_components, self.fd.read(length))[0]
				print(data)
		elif(format == 4):
			if(length <= 4):
				data = unpack(">L", self.fd.read(4))[0]
				print(data)
			else:
				data_offset = unpack(">L", self.fd.read(4))[0]
				#move back to 0x4d
				self.fd.seek(self.endian_offset)
				#read up to the data offset
				self.fd.read(data_offset)
				data = unpack(">L", self.fd.read(4))[0]
				print(data)
		#
		#WRONG
		#
		elif(format == 5):
			if(length <= 4):
				#will not compile with the following line of code:
				#(numerator, denominator) = unpack(">LL", self.fd.read(8))[0]
				print("%s/%s" % (numerator, denominator))
			else:
				data_offset = unpack(">L", self.fd.read(4))[0]
				#move back to 0x4d
				self.fd.seek(self.endian_offset)
				#read up to the data offset
				self.fd.read(data_offset)
				#will not compile with the following line of code:
				#(numerator, denominator) = unpack(">LL", self.fd.read(8))[0]
				print("%s/%s" % (numerator, denominator))
		#
		#WRONG
		#

		elif(format == 7):
			if(length <= 4):
				value = unpack(">%dB" % length, self.fd.read(length))[0]
				data = "".join("%c" % x for x in value)
				print(data)
			else:
				data_offset = unpack(">L", self.fd.read(4))[0]
				#move back to 0x4d
				self.fd.seek(self.endian_offset)
				#read up to the data offset
				self.fd.read(data_offset)
				value = unpack(">%dB" % length, self.fd.read(length))[0]
				data = "".join("%c" % x for x in value)
				print(data)

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
		file.check_jpeg()
	else:
		usage()


if __name__ == '__main__':
=======
#!/usr/bin/env python3
"""
Author: Jade Hedrick
HW3 CS365 Forensics, Spring 2015
"""
import sys
from tags import TAGS
from struct import unpack


JPEG_HEADER = b'\xff\xd8'

class exifDump:

	def __init__(self, filename):
		self.filename = filename
		self.fd = self.open_file()
		self.offset = 2
		self.endian_offset = 0

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

	def check_jpeg(self):
		"""
		Checks that the file is a JPEG. If it isn't, exits. 
		Else, continues to find markers.
		"""
		try:
			data = self.fd.read(2)
		except:
			print("Unexpected error while reading file:", sys.exc_info()[0])
			sys.exit()
		#if not JPEG	
		if(data != JPEG_HEADER):
			print("Warning: File is not a JPEG. Program will now exit.")
			sys.exit()
		else:
			self.find_markers()

	def find_markers(self):
		"""
		Cycles through the metadata of the JPEG. Makes call to check_exif_and_endian()
		for each marker. 
		"""
		marker_value = 0
		marker_location = 0
		marker_length = 0
		#run until FFDA marker
		while marker_value != int.from_bytes(b'\xFF\xDA', byteorder='big'):
			marker_location = self.fd.tell()
			try:
				marker_value = unpack(">H", self.fd.read(2))[0]
				marker_length = unpack(">H", self.fd.read(2))[0]
			except:
				print("Unexpected error while reading markers:", sys.exc_info()[0])
			print("[0x%04X]" % marker_location, end = " ")
			print("Marker 0x%04X" % marker_value, end = " ")
			print("size=0x%04X" % marker_length)
			self.check_exif_and_endian()
			self.offset = marker_location + 2 + marker_length
			self.fd.seek(self.offset)

	def check_exif_and_endian(self):
		"""
		Reads in first 6 bytes of marker headers. If exif, checks next 2 bytes for 
		endianness. If big endian, make call to get_IFD(), otherwise exit.
		"""	
		try:	
			data = self.fd.read(6)
		except:
			print("Unexpected read error while checking exif:", sys.exc_info()[0])
		#if exif
		if(data == b'Exif\x00\x00'):
			self.endian_offset = self.fd.tell()
			#if big endian
			if(self.fd.read(2) == b'MM'):
				#skip over 00 2a
				self.fd.read(2)
				self.get_IFD()
			else:
				print("Get back little endian scum! Program will exit for such insolence!")
				sys.exit()

	def get_IFD(self):
		"""
		Prints number of IFD entries. Parses IFD tags with call to format().
		"""
		bytes_per_component = (0,1,1,2,4,8,1,1,2,4,8,4,8)
		try:
			self.offset = unpack(">L", self.fd.read(4))[0]
			self.fd.read(self.offset - 8)
			num_entries = unpack(">H", self.fd.read(2))[0]
			print("Number of IFD Entries: ", num_entries)
		except:
			print("Unexpected read error while fetching number of IFD entries:", sys.exc_info()[0])
		#for num_entries
		for num in range(0, num_entries):
			#at this point we are at the beginning of an entry
			#here we save an index pointing to the next entry 12 bytes away
			next_tag = self.fd.tell() + 12
			tag = unpack(">H", self.fd.read(2))[0]
			print("%X" % tag, end = " ")
			print(TAGS[tag], end = " ")
			format = unpack(">H", self.fd.read(2))[0]
			num_of_components = unpack(">L", self.fd.read(4))[0]
			length = bytes_per_component[format]*num_of_components
			self.format(format, num_of_components, length)
			#no matter where we got to in format(), we only jump 12 bytes from the start of the loop
			self.fd.seek(next_tag)
			# if(length <= 4):
			# 	#WRONG
			# 	data = unpack(">L", self.fd.read(4))[0]
			# 	print(data)
			# 	#WRONG
			# else:
			# 	data = unpack(">L", self.fd.read(4))[0]
			# 	next_tag = self.fd.tell()
				#move back to 0x4d
				# self.fd.seek(self.endian_offset)
				# #read up to the data offset
				# self.fd.read(data)
				# print(self.fd.read(length).decode("utf-8").rjust(35))
				# #go to the next tag
				# self.fd.seek(next_tag)

	#the part where it stops looking pretty
	def format(self, format, num_of_components, length):
		format = format
		length = length
		numerator   = 1.0
		denominator = 1.0
		if(format == 1):
			if(length <= 4):
				data = unpack(">B", self.fd.read(1))[0]
				print(data)
			else:
				data_offset = unpack(">L", self.fd.read(4))[0]
				#move back to 0x4d
				self.fd.seek(self.endian_offset)
				#read up to the data offset
				self.fd.read(data_offset)
				data = unpack(">B", self.fd.read(1))[0]
				print(data)
		elif(format == 2):
			if(length <= 4):
				data = bytes.decode(self.fd.read(1))
				print(data)
			else:
				data_offset = unpack(">L", self.fd.read(4))[0]
				#move back to 0x4d
				self.fd.seek(self.endian_offset)
				#read up to the data offset
				self.fd.read(data_offset)
				data = bytes.decode(self.fd.read(length))
				print(data)
		elif(format == 3):
			if(length <= 4):
				data = unpack(">%dH" % num_of_components, self.fd.read(length))[0]
				print(data)
			else:
				data_offset = unpack(">L", self.fd.read(4))[0]
				#move back to 0x4d
				self.fd.seek(self.endian_offset)
				#read up to the data offset
				self.fd.read(data_offset)
				data = unpack(">%dH" % num_of_components, self.fd.read(length))[0]
				print(data)
		elif(format == 4):
			if(length <= 4):
				data = unpack(">L", self.fd.read(4))[0]
				print(data)
			else:
				data_offset = unpack(">L", self.fd.read(4))[0]
				#move back to 0x4d
				self.fd.seek(self.endian_offset)
				#read up to the data offset
				self.fd.read(data_offset)
				data = unpack(">L", self.fd.read(4))[0]
				print(data)
		elif(format == 5):
			if(length <= 4):
				(numerator, denominator) = unpack(">LL", self.fd.read(8))[0]
				print("%s/%s" % (numerator, denominator))
			else:
				data_offset = unpack(">L", self.fd.read(4))[0]
				#move back to 0x4d
				self.fd.seek(self.endian_offset)
				#read up to the data offset
				self.fd.read(data_offset)
				(numerator, denominator) = unpack(">LL", self.fd.read(8))[0]
				print("%s/%s" % (numerator, denominator))
		elif(format == 7):
			if(length <= 4):
				value = unpack(">%dB" % length, self.fd.read(length))[0]
				data = "".join("%c" % x for x in value)
				print(data)
			else:
				data_offset = unpack(">L", self.fd.read(4))[0]
				#move back to 0x4d
				self.fd.seek(self.endian_offset)
				#read up to the data offset
				self.fd.read(data_offset)
				value = unpack(">%dB" % length, self.fd.read(length))[0]
				data = "".join("%c" % x for x in value)
				print(data)

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
		file.check_jpeg()
	else:
		usage()


if __name__ == '__main__':
>>>>>>> 0bdce94ffb3e49ddec08a49cb40bdb5494c91eb8
	main()