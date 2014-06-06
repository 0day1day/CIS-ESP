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

def getSystemRegistry(computerName,objRegistry,hostPath,tmpIndicators):
	print computerName + " - checking system Registry"
	configFile = support.resource_path("config\\systemRegistry.txt")
	
	with open(configFile, "r") as keysFile:
		keys = keysFile.readlines()
	
	outFile = open(hostPath + "\SYSTEMREGISTRY-" + computerName + ".csv", "w")
	outFile.write("reg_path,reg_key,reg_value\n")
	
	keys = keys + tmpIndicators
	
	for key in keys:
		key = key.replace("\n","")
		result,subkeys = objRegistry.EnumKey(hDefKey=_winreg.HKEY_LOCAL_MACHINE,sSubKeyName=key)
		if result == 0:
			subkeys.append("") #check for the key without subkeys
			for subkey in subkeys:
				result,valueNames,valueTypes = objRegistry.EnumValues(hDefKey=_winreg.HKEY_LOCAL_MACHINE,sSubKeyName=key+"\\"+subkey)
				if result == 0:
					if valueTypes == None or len(valueTypes) == 0:
							outFile.write(key.replace(","," ") + "\\" + subkey.replace(","," ") + ",EMPTY,EMPTY\n")
					else:
						for x in range(0,len(valueNames)):
							support.printReg(_winreg.HKEY_LOCAL_MACHINE, valueNames[x], valueTypes[x], key+"\\"+subkey, outFile, objRegistry)
		else:
			outFile.write(key.replace(","," ") + ",DOES NOT EXIST,DOES NOT EXIST\n")
			
	outFile.close()
