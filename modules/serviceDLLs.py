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

def getServiceDLLs(computerName,objRegistry,hostPath):
	print computerName + " - checking service DLLs"
	outFile = open(hostPath + "\SERVICEDLLS-" + computerName + ".csv", "w")
	outFile.write("service,display_name,service_path,service_dll\n")
	
	key = "SYSTEM\CurrentControlSet\Services"
	result,subkeys = objRegistry.EnumKey(hDefKey=_winreg.HKEY_LOCAL_MACHINE,sSubKeyName=key)
	
	if result == 0:
		for subkey in subkeys:
			display_name = ""
			service_path = ""
			service_dll = ""
			
			result,valueNames,valueTypes = objRegistry.EnumValues(hDefKey=_winreg.HKEY_LOCAL_MACHINE,sSubKeyName=key+"\\"+subkey)
			if result == 0:
				if valueNames != None and len(valueNames) > 0:
					for value in valueNames:
						if value.upper() == "DisplayName".upper():
							result,display_name = objRegistry.GetStringValue(hDefKey=_winreg.HKEY_LOCAL_MACHINE,sSubKeyName=key+"\\"+subkey,sValueName=value)
							if result != 0:
								display_name = ""
						elif value.upper() == "ImagePath".upper():
							result,service_path = objRegistry.GetStringValue(hDefKey=_winreg.HKEY_LOCAL_MACHINE,sSubKeyName=key+"\\"+subkey,sValueName=value)
							if result != 0:
								service_path = ""
							
					result,service_dll = objRegistry.GetStringValue(hDefKey=_winreg.HKEY_LOCAL_MACHINE,sSubKeyName=key+"\\"+subkey+"\\Parameters",sValueName="ServiceDll")
					if result != 0:
						service_dll = ""
				
				display_name = support.convert_to_string(display_name)
				service_path = support.convert_to_string(service_path)
				service_dll = support.convert_to_string(service_dll)
				outFile.write(subkey.replace(","," ") + "," + display_name.replace(","," ") + "," + service_path.replace(","," ") + "," + service_dll.replace(","," ") + "\n")
		
	outFile.close()
