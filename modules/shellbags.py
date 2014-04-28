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

#This is a modified version of shellbags.py by Will Ballenthin
#Will Ballenthin, william.ballenthin@mandiant.com
#Copyright 2011 Will Ballenthin while at Mandiant
#
#https://github.com/williballenthin/shellbags
#The original file is licensed under the Apache License, Version 2.0

import _winreg
import re

from BinaryParser import Block
from BinaryParser import OverrunBufferException
from ShellItems import SHITEMLIST
from ShellItems import ITEMPOS_FILEENTRY

class ShellbagException(Exception):
	"""
	Base Exception class for shellbag parsing.
	"""
	def __init__(self, value):
		"""
		Constructor.
		Arguments:
		- `value`: A string description.
		"""
		super(ShellbagException, self).__init__()
		self._value = value

	def __str__(self):
		return str(unicode(self))

	def __unicode__(self):
		return u"Shellbag Exception: %s" % (self._value)

def get_shellbags(objRegistry,hive,shell_key):
	shellbags = []
	bagmru_key = shell_key+"\\BagMRU"
	bags_key = shell_key+"\\Bags"

	def shellbag_rec(hive,key,bag_prefix,path_prefix):
		try:
			# First, consider the current key, and extract shellbag items
			result,valueNames,valueTypes = objRegistry.EnumValues(hDefKey=hive,sSubKeyName=key)
			if result == 0:
				if valueTypes == None or len(valueTypes) == 0:
					pass
				else:
					for x in range(0,len(valueNames)):
						if valueNames[x] == "NodeSlot" and valueTypes[x] == _winreg.REG_DWORD:
							result,slot = objRegistry.GetDWORDValue(hDefKey=hive,sSubKeyName=key,sValueName=valueNames[x])
							slot = str(slot)
							if result == 0:
								result,subkeys = objRegistry.EnumKey(hDefKey=hive,sSubKeyName=bags_key+"\\"+slot)
								if result == 0:
									for bag in subkeys:
										result,valueNames2,valueTypes2 = objRegistry.EnumValues(hDefKey=hive,sSubKeyName=bags_key+"\\"+slot+"\\"+bag)
										if result == 0:
											if valueTypes2 == None or len(valueTypes2) == 0:
												pass
											else:
												for x in range(0,len(valueNames2)):
													if "ItemPos" in valueNames2[x] and valueTypes2[x] == _winreg.REG_BINARY:
														result,itemPos = objRegistry.GetBinaryValue(hDefKey=hive,sSubKeyName=bags_key+"\\"+slot+"\\"+bag,sValueName=valueNames2[x])
														if result == 0:
															cachebin = ""
															for decimal in itemPos:
																cachebin += chr(decimal)
															buf = cachebin
															block = Block(buf, 0x0, False)
															offset = 0x10

															while True:
																offset += 0x8
																size = block.unpack_word(offset)
																if size == 0:
																	break
																elif size < 0x15:
																	pass
																else:
																	item = ITEMPOS_FILEENTRY(buf, offset, False)
																	shellbags.append({
																		"path": path_prefix + "\\" + item.name(),
																		"mtime": item.m_date(),
																		"atime": item.a_date(),
																		"crtime": item.cr_date()
																	})
																offset += size
		except Exception as ex:
			print ex

		# Next, recurse into each BagMRU key
		result,valueNames,valueTypes = objRegistry.EnumValues(hDefKey=hive,sSubKeyName=key)
		if result == 0:
			if valueTypes == None or len(valueTypes) == 0:
				pass
			else:
				for x in range(0,len(valueNames)):
					if re.match("\d+", valueNames[x]) and valueTypes[x] == _winreg.REG_BINARY:
						result,reg_value = objRegistry.GetBinaryValue(hDefKey=hive,sSubKeyName=key,sValueName=valueNames[x])
						if result == 0:
							cachebin = ""
							for decimal in reg_value:
								cachebin += chr(decimal)
							buf = cachebin
							try:
								l = SHITEMLIST(buf, 0, False)
								for item in l.items():
									# assume there is only one entry in the value, or take the last
									# as the path component
									path = path_prefix + "\\" + item.name()
									shellbags.append({
										"path": path,
										"mtime": item.m_date(),
										"atime": item.a_date(),
										"crtime": item.cr_date()
									})
							except OverrunBufferException as ex:
								raise
							shellbag_rec(hive, key+"\\"+valueNames[x],bag_prefix + "\\" + valueNames[x],path)
	shellbag_rec(hive, bagmru_key, "", "")
	return shellbags

def getShellbags(objRegistry,hive,keys):
	shellbags = []

	for key in keys:
		new_shellbags = get_shellbags(objRegistry,hive,key)
		shellbags.extend(new_shellbags)

	return shellbags
