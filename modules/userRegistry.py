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
from modules import support

def pollReg(computerName,hostPath,username,hive,userpath,objRegistry,tmpIndicators):
	configFile = support.resource_path("config\\UserRegistry.txt")
	
	with open(configFile, "r") as keysFile:
		keys = keysFile.readlines()
	
	outFile = open(hostPath + "\USERREGISTRY-" + username + "-" + computerName + ".csv", "w")
	outFile.write("reg_path,reg_key,reg_value\n")
	
	keys = keys + tmpIndicators
	
	for key in keys:
		key = key.replace("\n","")
		if not key.startswith("\\"):
			key = "\\" + key
		fullkey = userpath + key
		
		if "UserAssist" in key:
			result,subkeys = objRegistry.EnumKey(hDefKey=hive,sSubKeyName=fullkey)
			if result == 0:
				for subkey in subkeys:
					result,valueNames,valueTypes = objRegistry.EnumValues(hDefKey=hive,sSubKeyName=fullkey+"\\"+subkey+"\\"+"Count")
					if result == 0:
						for value in valueNames:
							outFile.write(key.replace(","," ") + "," + str(value).encode('rot13').replace(","," ") + ",USERASSIST\n")
		else:
			result,subkeys = objRegistry.EnumKey(hDefKey=hive,sSubKeyName=fullkey)
			if result == 0:
				result,valueNames,valueTypes = objRegistry.EnumValues(hDefKey=hive,sSubKeyName=fullkey)
				if result == 0:
					if valueTypes == None or len(valueTypes) == 0:
						outFile.write(key.replace(","," ") + ",EMPTY,EMPTY\n")
					else:
						for x in range(0,len(valueNames)):
							support.printReg(hive, valueNames[x], valueTypes[x], fullkey, outFile, objRegistry, key)
			else:
				outFile.write(key.replace(","," ") + ",DOES NOT EXIST,DOES NOT EXIST\n")
				
	outFile.close()
	
def getUserRegistry(computerName,objRegistry,hostPath,tmpIndicators,registryList):
	print computerName + " - checking user Registry"
	
	for hive,username,userpath in registryList:
		if hive == _winreg.HKEY_LOCAL_MACHINE:
			print computerName + " - user Registry: checking logged out user (" + username + ")..."
		elif hive == _winreg.HKEY_USERS:
			print computerName + " - user Registry: checking logged in user (" + username + ")..."
		pollReg(computerName,hostPath,username,hive,userpath,objRegistry,tmpIndicators)					
