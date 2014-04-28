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

def getNetstatAndDNS(computerName,hostErrorLog,objProcWMI):
	print computerName + " - checking netstat"
	
	try:
		objProcWMI.Create(CommandLine="cmd.exe /c netstat.exe -naob > C:\NS.txt")
	except Exception as ex:
		hostErrorLog.write("netstat - " + str(ex) + "\n")
	
	print computerName + " - checking DNS"
	
	try:
		objProcWMI.Create(CommandLine="cmd.exe /c ipconfig /displaydns > C:\DNS.txt")
	except Exception as ex:
		hostErrorLog.write("DNS - " + str(ex) + "\n")