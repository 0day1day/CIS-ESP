#Copyright 2014 Center for Internet Security - Computer Emergency Response Team (CIS-CERT)
#This is part of the CIS Enumeration and Scanning Program (CIS-ESP)
#
#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License.
#You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#Unless required by applicable law or agreed to in writing, software
#distributed under the License is distributed on an "AS IS" BASIS,
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#See the License for the specific language governing permissions and
#limitations under the License.

#This is a modified version of ShimCacheParser.py by Andrew Davis/Mandiant
#Andrew Davis, andrew.davis@mandiant.com
#Copyright 2012 Mandiant
#
#https://github.com/mandiant/ShimCacheParser
#The original file is licensed under the Apache License, Version 2.0

import _winreg
import sys
import struct
import binascii
import datetime
import cStringIO as sio

from modules import support

# Values used by Windows 5.2 and 6.0 (Server 2003 through Vista/Server 2008)
CACHE_MAGIC_NT5_2 = 0xbadc0ffe
CACHE_HEADER_SIZE_NT5_2 = 0x8
NT5_2_ENTRY_SIZE32 = 0x18
NT5_2_ENTRY_SIZE64 = 0x20

# Values used by Windows 6.1 (Win7 and Server 2008 R2)
CACHE_MAGIC_NT6_1 = 0xbadc0fee
CACHE_HEADER_SIZE_NT6_1 = 0x80
NT6_1_ENTRY_SIZE32 = 0x20
NT6_1_ENTRY_SIZE64 = 0x30
CSRSS_FLAG = 0x2

# Values used by Windows 5.1 (WinXP 32-bit)
WINXP_MAGIC32 = 0xdeadbeef
WINXP_HEADER_SIZE32 = 0x190
WINXP_ENTRY_SIZE32 = 0x228
MAX_PATH = 520

# Values used by Windows 8 and Server 2012
WIN8_STATS_SIZE = 0x80
WIN8_MAGIC = '00ts'

# Magic value used by Windows 8.1 and Server 2012 R2
WIN81_MAGIC = '10ts'

bad_entry_data = ''
output_header  = ["Last Modified", "Last Update", "Path", "File Size", "Exec Flag"]

# Shim Cache format used by Windows 5.2 and 6.0 (Server 2003 through Vista/Server 2008)
class CacheEntryNt5(object):
	def __init__(self, is32bit, data=None):
		self.is32bit = is32bit
		if data != None:
			self.update(data)
			
	def update(self, data):
		if self.is32bit:
			entry = struct.unpack('<2H 3L 2L', data)
		else:
			entry = struct.unpack('<2H 4x Q 2L 2L', data)
		self.wLength = entry[0]
		self.wMaximumLength =  entry[1]
		self.Offset = entry[2]
		self.dwLowDateTime = entry[3]
		self.dwHighDateTime = entry[4]
		self.dwFileSizeLow = entry[5]
		self.dwFileSizeHigh = entry[6]
		
	def size(self):
		if self.is32bit:
			return NT5_2_ENTRY_SIZE32
		else:
			return NT5_2_ENTRY_SIZE64
			
# Shim Cache format used by Windows 6.1 (Win7 through Server 2008 R2)
class CacheEntryNt6(object):
	def __init__(self, is32bit, data=None):
		self.is32bit = is32bit
		if data != None:
			self.update(data)
			
	def update(self, data):
		if self.is32bit:
			entry = struct.unpack('<2H 7L', data)
		else:
			entry = struct.unpack('<2H 4x Q 4L 2Q', data)
		self.wLength = entry[0]
		self.wMaximumLength =  entry[1]
		self.Offset = entry[2]
		self.dwLowDateTime = entry[3]
		self.dwHighDateTime = entry[4]
		self.FileFlags = entry[5]
		self.Flags = entry[6]
		self.BlobSize = entry[7]
		self.BlobOffset = entry[8]
		
	def size(self):
		if self.is32bit:
			return NT6_1_ENTRY_SIZE32
		else:
			return NT6_1_ENTRY_SIZE64
			
# Convert FILETIME to datetime.
# Based on http://code.activestate.com/recipes/511425-filetime-to-datetime/
def convert_filetime(dwLowDateTime, dwHighDateTime):
	try:
		date = datetime.datetime(1601, 1, 1, 0, 0, 0)    
		temp_time = dwHighDateTime
		temp_time <<= 32
		temp_time |= dwLowDateTime
		return date + datetime.timedelta(microseconds=temp_time/10)
	except OverflowError, err:
		return None
		
# Return a unique list while preserving ordering.
def unique_list(li):
	ret_list = []
	for entry in li:
		if entry not in ret_list:
			ret_list.append(entry)
	return ret_list
	
# Write the Log.
def write_it(rows, outFile, computerName):
	try:
		if not rows:
			outFile.write("No data to write\n")
			return
			
		for row in rows:
			outFile.write(",".join(["%s"%x for x in row]) + "\n")
	except UnicodeEncodeError, err:
		print computerName + " - error writing output file: %s" % str(err)
		return

def read_cache(cachebin, computerName):
	if len(cachebin) < 16:
		# Data size less than minimum header size.
		return None
		
	try:
		magic = struct.unpack("<L", cachebin[0:4])[0]
		
		if magic == CACHE_MAGIC_NT5_2:
			print computerName + " - found Windows XP 64-bit, Vista, Server 2003, or Server 2008"
			test_size = struct.unpack("<H", cachebin[8:10])[0]
			test_max_size = struct.unpack("<H", cachebin[10:12])[0]
			if (test_max_size-test_size == 2 and struct.unpack("<L", cachebin[12:16])[0] ) == 0:
				print computerName + " - found 64-bit system"
				entry = CacheEntryNt5(False)
				return read_nt5_entries(cachebin, entry, computerName)
			else:
				print computerName + " - found 32-bit system"
				entry = CacheEntryNt5(True)
				return read_nt5_entries(cachebin, entry, computerName)
				
		elif magic == CACHE_MAGIC_NT6_1:
			print computerName + " - found Windows 7 or  Server 2008 R2"
			test_size = (struct.unpack("<H",cachebin[CACHE_HEADER_SIZE_NT6_1:CACHE_HEADER_SIZE_NT6_1 + 2])[0])
			test_max_size = (struct.unpack("<H", cachebin[CACHE_HEADER_SIZE_NT6_1+2:CACHE_HEADER_SIZE_NT6_1 + 4])[0])
			if (test_max_size-test_size == 2 and struct.unpack("<L", cachebin[CACHE_HEADER_SIZE_NT6_1+4:CACHE_HEADER_SIZE_NT6_1 + 8])[0] ) == 0:
				print computerName + " - found 64-bit system"
				entry = CacheEntryNt6(False)
				return read_nt6_entries(cachebin, entry, computerName)
			else:
				print computerName + " - found 32-bit system"
				entry = CacheEntryNt6(True)
				return read_nt6_entries(cachebin, entry, computerName)
				
		elif magic == WINXP_MAGIC32:
			print computerName + " - found Windows XP 32-bit"
			return read_winxp_entries(cachebin, computerName)
			
		elif len(cachebin) > WIN8_STATS_SIZE and cachebin[WIN8_STATS_SIZE:WIN8_STATS_SIZE+4] == WIN8_MAGIC:
			print computerName + " - found Windows 8 or Server 2012"
			return read_win8_entries(cachebin, WIN8_MAGIC, computerName)
			
		elif len(cachebin) > WIN8_STATS_SIZE and cachebin[WIN8_STATS_SIZE:WIN8_STATS_SIZE+4] == WIN81_MAGIC:
			print computerName + " - found Windows 8.1 or Server 2012 R2"
			return read_win8_entries(cachebin, WIN81_MAGIC, computerName)
			
		else:
			print computerName + " - unknown magic value of 0x%x" % magic
			return None

	except (RuntimeError, TypeError, NameError), err:
		print computerName + " - error reading shim cache data: %s" % err
		return None

# Read Windows 8/2k12/8.1 Apphelp Cache entry formats.
def read_win8_entries(bin_data, ver_magic, computerName):
	entry_meta_len = 12
	entry_list = []
	
	# Skip past the stats in the header
	cache_data = bin_data[WIN8_STATS_SIZE:]
	
	data = sio.StringIO(cache_data)
	while data.tell() < len(cache_data):
		header = data.read(entry_meta_len)
		# Read in the entry metadata
		# Note: the crc32 hash is of the cache entry data
		magic, crc32_hash, entry_len = struct.unpack('<4sLL', header)
		
		# Check the magic tag
		if magic != ver_magic:
			raise Exception("Invalid version magic tag found: 0x%x" % struct.unpack("<L", magic)[0])
			
		entry_data = sio.StringIO(data.read(entry_len))
		
		# Read the path length
		path_len = struct.unpack('<H', entry_data.read(2))[0]
		if path_len == 0:
			path = 'None'
		else:
			path = entry_data.read(path_len).decode('utf-16le', 'replace').encode('utf-8')
			
		# Check for package data
		package_len = struct.unpack('<H', entry_data.read(2))[0]
		if package_len > 0:
			# Just skip past the package data if present (for now)
			entry_data.seek(package_len, 1)
			
		# Read the remaining entry data
		flags, unk_1, low_datetime, high_datetime, unk_2 = struct.unpack('<LLLLL', entry_data.read(20)) 
		
		# Check the flag set in CSRSS
		if (flags & CSRSS_FLAG):
			exec_flag = 'True'
		else:
			exec_flag = 'False'
			
		last_mod_date = convert_filetime(low_datetime, high_datetime)
		try:
			last_mod_date = last_mod_date.strftime("%Y/%m/%d %H:%M:%S")
		except ValueError:
			last_mod_date = bad_entry_data
			
		row = [last_mod_date, bad_entry_data, support.convert_to_string(path).replace(","," "), bad_entry_data, exec_flag]
		entry_list.append(row)
		
	return entry_list

# Read Windows 2k3/Vista/2k8 Shim Cache entry formats.
def read_nt5_entries(bin_data, entry, computerName):
	try:
		entry_list = []
		contains_file_size = False
		entry_size = entry.size()
		exec_flag = ''
		
		num_entries = struct.unpack('<L', bin_data[4:8])[0]
		if num_entries == 0:
			return None
			
		# On Windows Server 2008/Vista, the filesize is swapped out of this
		# structure with two 4-byte flags. Check to see if any of the values in
		# "dwFileSizeLow" are larger than 2-bits. This indicates the entry contained file sizes.
		for offset in xrange(CACHE_HEADER_SIZE_NT5_2, (num_entries * entry_size),entry_size):
			entry.update(bin_data[offset:offset+entry_size])
			
			if entry.dwFileSizeLow > 3:
				contains_file_size = True
				break
				
		# Now grab all the data in the value.
		for offset in xrange(CACHE_HEADER_SIZE_NT5_2, (num_entries  * entry_size),entry_size):
			entry.update(bin_data[offset:offset+entry_size])
			last_mod_date = convert_filetime(entry.dwLowDateTime, entry.dwHighDateTime)
			try:
				last_mod_date = last_mod_date.strftime("%Y/%m/%d %H:%M:%S")
			except ValueError:
				last_mod_date = bad_entry_data
			path = bin_data[entry.Offset:entry.Offset + entry.wLength].decode('utf-16le', 'replace').encode('utf-8')
			path = path.replace("\\??\\", "")
			
			# It contains file size data.
			if contains_file_size:
				hit = [last_mod_date, bad_entry_data, support.convert_to_string(path).replace(","," "), str(entry.dwFileSizeLow), bad_entry_data]
				if hit not in entry_list:
					entry_list.append(hit)
					
			# It contains flags.
			else:
				# Check the flag set in CSRSS
				if (entry.dwFileSizeLow & CSRSS_FLAG):
					exec_flag = 'True'
				else:
					exec_flag = 'False'
					
				hit = [last_mod_date, bad_entry_data, support.convert_to_string(path).replace(","," "), bad_entry_data, exec_flag]
				if hit not in entry_list:
					entry_list.append(hit)
					
		return entry_list
	except (RuntimeError, ValueError, NameError), err:
		print computerName + " - error reading shim cache data: %s..." % err
		return None
		
# Read the Shim Cache Windows 7/2k8-R2 entry format,
# return a list of last modifed dates/paths.
def read_nt6_entries(bin_data, entry, computerName):
	try:
		entry_list = []
		exec_flag = ""
		entry_size = entry.size()
		num_entries = struct.unpack('<L', bin_data[4:8])[0]
		
		if num_entries == 0:
			return None
			
		# Walk each entry in the data structure. 
		for offset in xrange(CACHE_HEADER_SIZE_NT6_1,num_entries*entry_size,entry_size):
			entry.update(bin_data[offset:offset+entry_size])
			last_mod_date = convert_filetime(entry.dwLowDateTime,entry.dwHighDateTime)
			try:
				last_mod_date = last_mod_date.strftime("%Y/%m/%d %H:%M:%S")
			except ValueError:
				last_mod_date = bad_entry_data
			path = (bin_data[entry.Offset:entry.Offset + entry.wLength].decode('utf-16le','replace').encode('utf-8'))
			path = path.replace("\\??\\", "")
			
			# Test to see if the file may have been executed.
			if (entry.FileFlags & CSRSS_FLAG):
				exec_flag = 'True'
			else:
				exec_flag = 'False'
				
			hit = [last_mod_date, bad_entry_data, support.convert_to_string(path).replace(","," "), bad_entry_data, exec_flag]
			
			if hit not in entry_list:
				entry_list.append(hit)
		return entry_list
	except (RuntimeError, ValueError, NameError), err:
		print computerNAme + " - error reading shim cache data: %s..." % err
		return None
		
# Read the WinXP Shim Cache data. Some entries can be missing data but still
# contain useful information, so try to get as much as we can.
def read_winxp_entries(bin_data, computerName):
	entry_list = []
	
	try:
		num_entries = struct.unpack('<L', bin_data[8:12])[0]
		if num_entries == 0:
			return None
			
		for offset in xrange(WINXP_HEADER_SIZE32,(num_entries*WINXP_ENTRY_SIZE32), WINXP_ENTRY_SIZE32):
			# No size values are included in these entries, so search for utf-16 terminator.
			path_len = bin_data[offset:offset+(MAX_PATH + 8)].find("\x00\x00")
			
			# if path is corrupt, procede to next entry.
			if path_len == 0:
				continue
			path =  bin_data[offset:offset+path_len + 1].decode('utf-16le').encode('utf-8')
			
			# Clean up the pathname.
			path = path.replace('\\??\\', '')
			if len(path) == 0: continue
			
			entry_data = (offset+(MAX_PATH+8))
			
			# Get last mod time.
			last_mod_time = struct.unpack('<2L', bin_data[entry_data:entry_data+8])
			try:
				last_mod_time = convert_filetime(last_mod_time[0],last_mod_time[1]).strftime("%Y/%m/%d %H:%M:%S")
			except ValueError:
				last_mod_time = bad_entry_data
				
			# Get last file size.
			file_size = struct.unpack('<2L', bin_data[entry_data + 8:entry_data + 16])[0]
			if file_size == 0:
				file_size = bad_entry_data
			
			# Get last update time.
			exec_time = struct.unpack('<2L', bin_data[entry_data + 16:entry_data + 24])
			try:
				exec_time = convert_filetime(exec_time[0],exec_time[1]).strftime("%Y/%m/%d %H:%M:%S")
			except ValueError:
				exec_time = bad_entry_data
				
			hit = [last_mod_time, exec_time, support.convert_to_string(path).replace(","," "), file_size, bad_entry_data]
			if hit not in entry_list:
				entry_list.append(hit)
		return entry_list
	except (RuntimeError, ValueError, NameError), err:
		print computerName + " - error reading shim cache data %s" % err
		return None
		
def getShimCache(computerName,objRegistry,hostPath):
	print computerName + " - checking shim cache"
	outFile = open(hostPath + "\SHIMCACHE-" + computerName + ".csv", "w")
	
	key = "SYSTEM"
	result,subkeys = objRegistry.EnumKey(hDefKey=_winreg.HKEY_LOCAL_MACHINE,sSubKeyName=key)
	doContinue = False
	
	if result != 0:
		outFile.write("Did not find SYSTEM key\n")
		return
	else: # if result == 0:
		for subkey in subkeys:
			if "CONTROLSET" in subkey.upper():
				key = key + "\\" + subkey
				doContinue = True
				break
		
		if not doContinue:
			outFile.write("Did not file ControlSet key\n")
			return
		else:
			key = key + "\\Control\\Session Manager"
			result,subkeys = objRegistry.EnumKey(hDefKey=_winreg.HKEY_LOCAL_MACHINE,sSubKeyName=key)
			doContinue = False
			
			for subkey in subkeys:
				if "APPCOMPAT" in subkey.upper():
					key = key + "\\" + subkey
					doContinue = True
					break
					
			if not doContinue:
				outFile.write("Did not file AppCompatCache key\n")
				return
			else:
				value = "AppCompatCache"
				result,bin_data = objRegistry.GetBinaryValue(hDefKey=_winreg.HKEY_LOCAL_MACHINE,sSubKeyName=key,sValueName=value)

				tmpcache = ""
				for decimal in bin_data:
					#r_value += "\\x%0.2X" % decimal
					tmpcache += chr(decimal)
				bin_data = tmpcache
				
				tmp_list = read_cache(bin_data, computerName)
				if tmp_list and len(tmp_list) > 0:
					tmp_list.insert(0, output_header)
				write_it(tmp_list,outFile, computerName)