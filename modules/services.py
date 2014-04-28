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

from modules import support

def getServices(computerName,objWMIService,hostPath):
	print computerName + " - checking services"
	outFile = open(hostPath + "\SERVICES-" + computerName + ".csv", "w")
	outFile.write("service,path,install_date,pid,start_mode,account,state,description\n")
	
	services = objWMIService.ExecQuery("Select Name,PathName,InstallDate,ProcessId,StartMode,StartName,State,Description from Win32_Service")
	for service in services:
		serviceName = support.convert_to_string(service.Name)
		servicePathName = support.convert_to_string(service.PathName)
		
		serviceInstallDate = support.convertDate(support.convert_to_string(service.InstallDate))
			
		serviceProcessId = support.convert_to_string(service.ProcessId)
		serviceStartMode = support.convert_to_string(service.StartMode)
		serviceStartName = support.convert_to_string(service.StartName)
		serviceState = support.convert_to_string(service.State)
		serviceDescription = support.convert_to_string(service.Description).replace("\n"," ")
			
		outFile.write(serviceName.replace(","," ") + "," + servicePathName.replace(","," ") + "," + serviceInstallDate + "," + 
			serviceProcessId.replace(","," ") + "," + serviceStartMode.replace(","," ") + "," + serviceStartName.replace(","," ") + "," + 
			serviceState.replace(","," ") + "," + serviceDescription.replace(","," ") + "\n")
		
	outFile.close()
