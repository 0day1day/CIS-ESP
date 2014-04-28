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

def breakFile(fStr):
	drive = ""
	path = ""
	filename = ""
	extension = ""
	
	if fStr == None:
		return [drive,path,filename,extension]
	
	pos1 = fStr.find(":")
	if pos1 >= 0:
		drive = fStr[0:pos1+1]
	
	pos2 = fStr.rfind("\\")
	if pos2 >= 0:
		path = fStr[pos1+1:pos2+1]
		path = path.replace("\\","\\\\")
	
	pos3 = fStr.rfind(".")
	if pos3 >= 0 and pos3 > pos2:
		extension = fStr[pos3+1:]
		filename = fStr[pos2+1:pos3]
	elif pos2 >= 0:
		filename = fStr[pos2+1:]
	else:
		filename = fStr
	
	return [drive,path,filename,extension]

def getDataExists(computerName,objWMIService,hostPath,tmpIndicators):
	print computerName + " - checking for file existence"
	configFile = support.resource_path("config\\DataExists.txt")
	fileList = open(configFile, "r").readlines()
	outFile = open(hostPath + "\DATAEXISTS-" + computerName + ".csv", "w")
	outFile.write("file,exists\n")
	
	fileList = fileList + tmpIndicators
	
	for f in fileList:
		f = f.strip()
		if len(f) > 0:
			drive,path,filename,extension = breakFile(f)
			query = "Select * From CIM_DataFile" 
			whereClause = False
			requiresAnd = False
			
			if len(filename) > 0:
				if not whereClause:
					query += " WHERE"
					whereClause = True
				elif requiresAnd:
					query += " AND"
				query += " FileName = \"" + filename + "\""
				requiresAnd = True
			
			if len(path) > 0:
				if not whereClause:
					query += " WHERE"
					whereClause = True
				elif requiresAnd:
					query += " AND"
				query += " Path = \"" + path + "\""
				requiresAnd = True
			
			if len(extension) > 0:
				if not whereClause:
					query += " WHERE"
					whereClause = True
				elif requiresAnd:
					query += " AND"
				query += " Extension = \"" + extension + "\""
				requiresAnd = True
			
			if len(drive) > 0:
				if not whereClause:
					query += " WHERE"
					whereClause = True
				elif requiresAnd:
					query += " AND"
				query += " DRIVE = \"" + drive + "\""
				requiresAnd = True
			
			colItems = objWMIService.ExecQuery(query)
			
			if len(colItems) > 0:
				print computerName + " - FILE FOUND: " + f
				outFile.write(f + ",1\n")
			else:
				outFile.write(f + ",0\n")
		
	outFile.close()
