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

def getProcesses(computerName,objWMIService,hostPath):
	print computerName + " - checking processes and process modules"
	outFile = open(hostPath + "\PROCESSES-" + computerName + ".csv", "w")
	outFile.write("process,pid,creation_date,process_owner,threat_count,path,cmd_line,ppid\n")
	outFile2 = open(hostPath + "\PROCESSMODULES-" + computerName + ".csv", "w")
	outFile2.write("pid,module_path\n")
	
	processes = objWMIService.ExecQuery("select Name,ProcessID,CreationDate,ThreadCount,ExecutablePath,CommandLine,ParentProcessID from Win32_Process") #can't get process owner with this method
	
	for process in processes:
		try:
			owner = process.ExecMethod_("GetOwner")
			username = support.convert_to_string(owner.Domain) + "\\" + support.convert_to_string(owner.User)
		except:
			username = ""
		processID = process.ProcessID
		
		processName = support.convert_to_string(process.Name)
		processId = support.convert_to_string(process.ProcessId)
		processCreationDate = support.convertDate(support.convert_to_string(process.CreationDate))
		processThreadCount = support.convert_to_string(process.ThreadCount)
		processExecutablePath = support.convert_to_string(process.ExecutablePath)
		processCommandLine = support.convert_to_string(process.CommandLine)
		processParentProcessId = support.convert_to_string(process.ParentProcessId)
		
		outFile.write(processName.replace(","," ") + "," + processId + "," + processCreationDate + "," + 
			username.replace(","," ") + "," + processThreadCount + "," + processExecutablePath.replace(","," ") + "," + 
			processCommandLine.replace(","," ") + "," + processParentProcessId + "\n")
		
		modules = objWMIService.ExecQuery("associators of {win32_process.handle='" + processId + "'} where AssocClass = CIM_ProcessExecutable")
		
		try:
			for module in modules:
				moduleName = support.convert_to_string(module.Name)
				outFile2.write(processId + "," + moduleName.replace(","," ") + "\n")
		except:
			pass
			
	outFile2.close()
	outFile.close()