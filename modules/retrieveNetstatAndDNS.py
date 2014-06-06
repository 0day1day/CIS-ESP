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

import time

def isFileOpen(command, computerName, objWMIService):
	query = "SELECT * FROM Win32_Process WHERE CommandLine LIKE '%" + command + "%'"
	processes = objWMIService.ExecQuery(query)
	
	if len(processes) > 0:
		return True
	
	return False

def retrieveNetstatAndDNS(computerName,hostErrorLog,objWMIService,objProcWMI,hostPath):
	print computerName + " - retrieving netstat and DNS output"
	
	try:
		outFile = open(hostPath + "\DNS-" + computerName + ".txt", "w")
		inFileStr = "\\\\" + computerName + "\\C$\\DNS.txt"

		while isFileOpen("cmd.exe /c ipconfig /displaydns > C:\\\\DNS.txt", computerName, objWMIService):
			time.sleep(1)
			print computerName + " - waiting for DNS process to finish..."
		
		with open(inFileStr, "r") as inFile:
			outFile.write(inFile.read())
		objProcWMI.Create(CommandLine="cmd.exe /c copy nul C:\DNS.txt") #on some systems, the file can't be deleted remotely
	except Exception as ex:
		hostErrorLog.write("retrieve DNS - " + str(ex) + "\n")
	finally:
		outFile.close()
	
	try:
		outFile = open(hostPath + "\NETSTAT-" + computerName + ".txt", "w")
		inFileStr = "\\\\" + computerName + "\\C$\\NS.txt"

		while isFileOpen("cmd.exe /c netstat.exe -naob > C:\\\\NS.txt", computerName, objWMIService):
			time.sleep(1)
			print computerName + " - waiting for netstat process to finish..."
		
		with open(inFileStr, "r") as inFile:
			outFile.write(inFile.read())
		objProcWMI.Create(CommandLine="cmd.exe /c copy nul C:\NS.txt") #on some systems, the file can't be deleted remotely
	except Exception as ex:
		hostErrorLog.write("retrieve netstat - " + str(ex) + "\n")
	finally:
		outFile.close()
	
	try:
		while isFileOpen("cmd.exe /c copy nul C:\\\\DNS.txt", computerName, objWMIService):
			time.sleep(1)
		objProcWMI.Create(CommandLine="cmd.exe /c del /F C:\DNS.txt")
		
		while isFileOpen("cmd.exe /c copy nul C:\\\\NS.txt", computerName, objWMIService):
			time.sleep(1)
		objProcWMI.Create(CommandLine="cmd.exe /c del /F C:\NS.txt")
	except Exception as ex:
		hostErrorLog.write("removing DNS.txt and NS.txt - " + str(ex) + "\n")
	