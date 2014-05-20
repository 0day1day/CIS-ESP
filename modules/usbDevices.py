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

import _winreg
import binascii

class usbEntry(object):
	def __init__(self, data):
		self.initialize(data)
			
	def initialize(self, data):
		self.vendor = data["vendor"]
		self.product = data["product"]
		self.version = data["version"]
		self.serialNumber = data["serialNumber"]
		self.parentIdPrefix = data["parentIdPrefix"]
		self.friendlyName = data["friendlyName"]
		self.driveLetter = "None detected"
		self.volumeGuid = ""
		self.binData = ""
		self.firstUsed = "Not seen in setupapi.log"
		self.lastUsed = "Cannot get key last written time remotely"
		self.user = ""
		
	def addUser(self, user):
		if not self.user:
			self.user = user
		else:
			self.user = self.user + ", " + user
		
def getUsbDevices(computerName,objRegistry,hostPath,registryList):
	print computerName + " - checking USB devices"
	outFile = open(hostPath + "\USBDEVICES-" + computerName + ".csv", "w")
	usbDevices = []
	
	hive = _winreg.HKEY_LOCAL_MACHINE
	key = "SYSTEM\\CurrentControlSet\\Control\\StorageDevicePolicies"
	value = "WriteProtect"
	result,reg_value = objRegistry.GetDWORDValue(hDefKey=hive,sSubKeyName=key,sValueName=value)
	if result == 0:
		if reg_value == 0:
			outFile.write("USB Write Protect - OFF\n")
		else:
			outFile.write("USB Write Protect - ON\n")
	else:
		outFile.write("USB Write Protect - UNKNOWN\n")
	
	key = "SYSTEM\\CurrentControlSet\\Services\\USBSTOR"
	value = "Start"
	result,reg_value = objRegistry.GetDWORDValue(hDefKey=hive,sSubKeyName=key,sValueName=value)
	if result == 0:
		if reg_value == 3:
			outFile.write("USB Devices Disabled - OFF\n")
		else:
			outFile.write("USB Devices Disabled - ON\n")
	else:
		outFile.write("USB Devices Disabled - UNKNOWN\n")
	
	key = "SYSTEM\\CurrentControlSet\\Enum\\USBSTOR"
	result,subkeys = objRegistry.EnumKey(hDefKey=hive,sSubKeyName=key)
	if result == 0:
		for subkey in subkeys:
			usbSplit = subkey.split("&")
			dict = {}
			
			for part in usbSplit:
				if part.startswith("Ven_"):
					dict["vendor"] = part[part.find("_")+1:]
				elif part.startswith("Prod_"):
					dict["product"] = part[part.find("_")+1:]
				elif part.startswith("Rev_"):
					dict["version"] = part[part.find("_")+1:]
					
			result,subkeys2 = objRegistry.EnumKey(hDefKey=hive,sSubKeyName=key+"\\"+subkey)
			if result == 0:
				for subkey2 in subkeys2:
					dict["serialNumber"] = subkey2
					value = "ParentIdPrefix"
					result,reg_value = objRegistry.GetStringValue(hDefKey=hive,sSubKeyName=key+"\\"+subkey+"\\"+subkey2,sValueName=value)
					if result == 0:
						dict["parentIdPrefix"] = reg_value
					else:
						dict["parentIdPrefix"] = ""
					value = "FriendlyName"
					result,reg_value = objRegistry.GetStringValue(hDefKey=hive,sSubKeyName=key+"\\"+subkey+"\\"+subkey2,sValueName=value)
					if result == 0:
						dict["friendlyName"] = reg_value
					else:
						dict["friendlyName"] = ""
						
				usbDevices.append(usbEntry(dict))
				
		key = "SYSTEM\\MountedDevices"
		result,valueNames,valueTypes = objRegistry.EnumValues(hDefKey=hive,sSubKeyName=key)
		if result == 0:
			if valueTypes == None or len(valueTypes) == 0:
					outFile.write(key + " - No Devices Found\n")
			else:
				for x in range(0,len(valueNames)):
					result,reg_value = objRegistry.GetBinaryValue(hDefKey=hive,sSubKeyName=key,sValueName=valueNames[x])
					r_value = ""
					if result == 0:
						for decimal in reg_value:
							r_value += "%0.2X" % decimal
					reg_value = r_value
					if len(reg_value) > 24:
						bin_data = binascii.unhexlify(reg_value).decode("utf-16")
						prefix = bin_data.split("#")[2].replace("&RM","")
						for device in usbDevices:
							if device.parentIdPrefix == prefix:
								device.binData = bin_data
								if "\\DosDevices\\" in valueNames[x]:
									driveLetter = valueNames[x][len("\\DosDevices\\"):]
									device.driveLetter = driveLetter
								elif "\\??\\Volume" in valueNames[x]:
									volumeGuid = valueNames[x][len("\\??\\Volume"):]
									device.volumeGuid = volumeGuid
									for user_hive,username,userpath in registryList:
										mountKey = userpath + "\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\" + volumeGuid
										result,_ = objRegistry.EnumKey(hDefKey=user_hive,sSubKeyName=mountKey)
										if result == 0:
											device.addUser(username)
									
	#SYSTEM\CurrentControlSet\Control\DeviceClasses\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}\.*SerialNumber.*
	#last time used (from last time written?)
	#cannot get this data remotely
	
	inFileStr = "\\\\" + computerName + "\\C$\\Windows\\setupapi.log"
	setupApiLog = ""
	try:
		with open(inFileStr, "r") as inFile:
			setupApiLog = inFile.read()
	except:
		pass
		
	outFile.write("\nUSB Devices:\n")
	for device in usbDevices:
		outFile.write(device.friendlyName + "\n")
		outFile.write("Vendor: " + device.vendor + "\n")
		outFile.write("Product: " + device.product + "\n")
		outFile.write("Version: " + device.version + "\n")
		outFile.write("Serial Number: " + device.serialNumber + "\n")
		outFile.write("Parent ID Prefix: " + device.parentIdPrefix + "\n")
		outFile.write("Drive Letter: " + device.driveLetter + "\n")
		outFile.write("Volume GUID: " + device.volumeGuid + "\n")
		outFile.write("SYSTEM\\MountedDevices Binary Data: " + device.binData + "\n")
		
		serialLocation = setupApiLog.find(device.serialNumber)
		firstTimeStart = setupApiLog.rfind("\n[",0,serialLocation)+2
		firstTimeEnd = setupApiLog.find("]",firstTimeStart)
		if serialLocation >= 0 and firstTimeStart >= 2 and firstTimeEnd >= 0:
			firstTimeEntry = setupApiLog[firstTimeStart:firstTimeEnd]
			firstTimeSplit = firstTimeEntry.split(" ")
			if len(firstTimeSplit) >= 2:
				device.firstUsed = firstTimeSplit[0] + " " + firstTimeSplit[1]
			
		outFile.write("First Used: " + device.firstUsed + "\n")
		outFile.write("Last Used: " + device.lastUsed + "\n")
		outFile.write("User: " + device.user + "\n")
		outFile.write("\n")
