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

def getUserDataExists(computerName,objWMIService,objRegistry,hostPath,tmpIndicators):
	print computerName + " - checking for user file existence"
	outFile = open(hostPath + "\USERDATAEXISTS-" + computerName + ".csv", "w")
	outFile.write("file,exists\n")
	
	key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"
	result,subkeys = objRegistry.EnumKey(hDefKey=_winreg.HKEY_LOCAL_MACHINE,sSubKeyName=key)
	if result == 0:
		userDirectories = []
		
		for subkey in subkeys:
			path = key + "\\" + subkey
			value = "ProfileImagePath"
			result,user_home = objRegistry.GetExpandedStringValue(hDefKey=_winreg.HKEY_LOCAL_MACHINE,sSubKeyName=path,sValueName=value)
			if result == 0:
				userDirectories.append(user_home.replace("\\","\\\\"))
			
		configFile = support.resource_path("config\\UserDataExists.txt")
		
		with open(configFile, "r") as fileListFile:
			fileList = fileListFile.readlines()
		
		fileList = fileList + tmpIndicators
		
		for file in fileList:
			file = file.replace("\n","").replace("\\","\\\\")
			
			for dir in userDirectories:
				fullPath = dir + "\\\\" + file
				files = objWMIService.ExecQuery("Select * From CIM_Datafile Where Name = '" + fullPath + "'")
				fullPath = fullPath.replace("\\\\","\\")
				
				if len(files) > 0:
					print computerName + " - FILE FOUND: " + fullPath
					outFile.write(fullPath + ",1\n")
				else:
					outFile.write(fullPath + ",0\n")
				
	outFile.close()
