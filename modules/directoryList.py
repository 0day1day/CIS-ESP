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

def getDirectoryList(computerName,objWMIService,hostPath,tmpIndicators):
	print computerName + " - enumerating directory lists"
	outFile = open(hostPath + "\DIRECTORYLIST-" + computerName + ".csv", "w")
	outFile.write("directory,created,modified,last_accessed\n")
	configFile = support.resource_path("config\\DirectoryList.txt")
	
	with open(configFile, "r") as scanPathsFile:
		scanPaths = scanPathsFile.readlines()
	
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
		
		#path must contain the drive in associators query - for some reason you cant split Path and Drive in this query - also paths must not contain trailing slash
		#query = "Associators of {Win32_Directory.Name='" + path + "'} WHERE AssocClass = Win32_Subdirectory ResultRole = PartComponent"
		query = "Select Name,CreationDate,LastModified,LastAccessed From WIN32_Directory Where Path = \"" + path + "\""
		
		if drive:
			query += " And Drive = \"" + drive + "\""
		
		dirlist = objWMIService.ExecQuery(query)
		
		try:
			for dir in dirlist:
				dirname = support.convert_to_string(dir.Name)
				outFile.write(dirname.replace(","," ") + "," + support.convertDate(dir.CreationDate) + "," + support.convertDate(dir.LastModified) + "," + 
					support.convertDate(dir.LastAccessed) + "\n")
		except:
			pass
			
	outFile.close()
