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
from modules import shellbags
from modules import support

def getLoginStatus(profile_path,profileSID,username,objRegistry):
	result,subkeys = objRegistry.EnumKey(hDefKey=_winreg.HKEY_USERS,sSubKeyName=profileSID)
	if result == 0:
		return [_winreg.HKEY_USERS,profileSID]
	else:
		return [_winreg.HKEY_LOCAL_MACHINE,username]

def pollReg(computerName,hostPath,username,hive,userpath,objRegistry,tmpIndicators,doUserRegistry,doShellbags):
	if doUserRegistry:
		configFile = support.resource_path("config\\UserRegistry.txt")
		keys = open(configFile, "r").readlines()
		outFile = open(hostPath + "\USERREGISTRY-" + username + "-" + computerName + ".csv", "w")
		outFile.write("reg_path,reg_key,reg_value\n")
		
		keys = keys + tmpIndicators
		
		for key in keys:
			key = key.replace("\n","")
			if not key.startswith("\\"):
				key = "\\" + key
			key = userpath + key
			
			if "UserAssist" in key:
				result,subkeys = objRegistry.EnumKey(hDefKey=hive,sSubKeyName=key)
				if result == 0:
					for subkey in subkeys:
						result,valueNames,valueTypes = objRegistry.EnumValues(hDefKey=hive,sSubKeyName=key+"\\"+subkey+"\\"+"Count")
						if result == 0:
							for value in valueNames:
								outFile.write(key.replace(","," ") + "," + str(value).encode('rot13').replace(","," ") + ",USERASSIST\n")
			else:
				result,subkeys = objRegistry.EnumKey(hDefKey=hive,sSubKeyName=key)
				if result == 0:
					result,valueNames,valueTypes = objRegistry.EnumValues(hDefKey=hive,sSubKeyName=key)
					if result == 0:
						if valueTypes == None or len(valueTypes) == 0:
							outFile.write(key.replace(","," ") + ",EMPTY,EMPTY\n")
						else:
							for x in range(0,len(valueNames)):
								support.printReg(hive, valueNames[x], valueTypes[x], key, outFile, objRegistry)
				else:
					outFile.write(key.replace(","," ") + ",DOES NOT EXIST,DOES NOT EXIST\n")
					
		outFile.close()
	if doShellbags:
		if hive == _winreg.HKEY_LOCAL_MACHINE:
			userpath2 = userpath + "2"
		else:
			userpath2 = userpath + "\Software\Classes"
		
		keys = [userpath + "\Software\Microsoft\Windows\Shell", userpath + "\Software\Microsoft\Windows\ShellNoRoam",
			userpath2 + "\Local Settings\Software\Microsoft\Windows\Shell", userpath2 + "\Local Settings\Software\Microsoft\Windows\ShellNoRoam"]
		
		all_shellbags = shellbags.getShellbags(objRegistry,hive,keys)
		outFile = open(hostPath + "\SHELLBAGS-" + username + "-" + computerName + ".csv", "w")
		outFile.write("path,created,modified,accessed\n")
		for shellbag in all_shellbags:
			outFile.write(support.convert_to_string(shellbag["path"]).replace(","," ") + "," + support.convert_to_string(shellbag["crtime"]) + "," + 
				support.convert_to_string(shellbag["mtime"]) + "," + support.convert_to_string(shellbag["atime"]) + "\n")
		outFile.close()
	
def getUserRegistry(computerName,objRegistry,objProcWMI2,hostPath,tmpIndicators,doUserRegistry,doShellbags):
	if doUserRegistry:
		print computerName + " - checking user Registry"
	if doShellbags:
		print computerName + " - checking shellbags"
	
	key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
	result,subkeys = objRegistry.EnumKey(hDefKey=_winreg.HKEY_LOCAL_MACHINE,sSubKeyName=key)
	
	if result == 0:
		for subkey in subkeys:
			result,profile_path = objRegistry.GetExpandedStringValue(hDefKey=_winreg.HKEY_LOCAL_MACHINE,sSubKeyName=key+"\\"+subkey,sValueName="ProfileImagePath")
			if result == 0 and ("Documents and Settings" in profile_path or "Users" in profile_path):
				username = profile_path[profile_path.rindex("\\")+1:]
				
				hive,userpath = getLoginStatus(profile_path,subkey,username,objRegistry)
				
				if hive == _winreg.HKEY_LOCAL_MACHINE:
					if doUserRegistry:
						pid,result = objProcWMI2.Create(CommandLine="cmd.exe /c reg load HKLM\\" + username + " \"" + profile_path + "\\ntuser.dat\"")
						print computerName + " - user Registry: checking logged out user (" + username + ")..."
					if doShellbags:
						pid,result = objProcWMI2.Create(CommandLine="cmd.exe /c reg load HKLM\\" + username + "2 \"" + profile_path + "\\AppData\\Local\\Microsoft\\Windows\\usrclass.dat\"")
						print computerName + " - shellbags: checking logged out user (" + username + ")..."
					#check if process is finished/has terminated
					pollReg(computerName,hostPath,username,hive,userpath,objRegistry,tmpIndicators,doUserRegistry,doShellbags)
					if doUserRegistry:
						pid,result = objProcWMI2.Create(CommandLine="cmd.exe /c reg unload HKLM\\" + username)
					if doShellbags:
						pid,result = objProcWMI2.Create(CommandLine="cmd.exe /c reg unload HKLM\\" + username + "2")
				elif hive == _winreg.HKEY_USERS:
					if doUserRegistry:
						print computerName + " - user Registry: checking logged in user (" + username + ")..."
					if doShellbags:
						print computerName + " - shellbags: checking logged in user (" + username + ")..."
					pollReg(computerName,hostPath,username,hive,userpath,objRegistry,tmpIndicators,doUserRegistry,doShellbags)
