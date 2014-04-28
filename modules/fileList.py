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

def getFileList(computerName,objWMIService,hostPath,tmpIndicators):
	print computerName + " - checking file lists"
	outFile = open(hostPath + "\FILELIST-" + computerName + ".csv", "w")
	outFile.write("file,created,modified,last_accessed,size\n")
	configFile = support.resource_path("config\\FileList.txt")
	scanPaths = open(configFile, "r").readlines()
	
	scanPaths = scanPaths + tmpIndicators
	
	for path in scanPaths:
		path = path.replace("\n","")
		if not path.strip():
			continue
		if "\\" != path[-1:]:
			path = path + "\\"
		path = path.replace("\\","\\\\")
		drivePos = path.find(":")+1
		drive = path[0:drivePos]
		path = path[drivePos:]
		
		query = "Select Name,CreationDate,LastModified,LastAccessed,FileSize From CIM_DataFile Where Path = \"" + path + "\""
		
		if drive:
			query += " And Drive = \"" + drive + "\""
			
		filelist = objWMIService.ExecQuery(query)
		
		for file in filelist:
			filename = support.convert_to_string(file.Name)
			filesize = support.convert_to_string(file.FileSize)
			outFile.write(filename.replace(","," ") + "," + support.convertDate(file.CreationDate) + "," + support.convertDate(file.LastModified) + "," + 
				support.convertDate(file.LastAccessed) + "," + filesize + "\n")
			
	outFile.close()
