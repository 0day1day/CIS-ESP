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

import active_directory
import datetime
import os
import sys
import wmi
import _winreg

#order of tests in bitstring
test_dict_readable = {
	"Netstat": 0,
	"UserRegistry": 1,
	"FileList": 2,
	"SystemRegistry": 3,
	"Processes": 4,
	"Tasks": 5,
	"Services": 6,
	"ServiceDlls": 7,
	"LocalAccounts": 8,
	"DataExists": 9,
	"ShimCache": 10,
	"UserDataExists": 11,
	"DirectoryList": 12,
	"Shellbags": 13
}

test_dict = dict((k.lower(), v) for k,v in test_dict_readable.iteritems())

def getPossibleTests():
	testsStr = ""
	for key in test_dict_readable:
		if testsStr:
			testsStr += ", "
		testsStr += key
	return testsStr

#the bitstring indicating number of tests
def run_all_tests():
	return "1"*len(test_dict)

def run_no_tests():
	return "0"*len(test_dict)

def runtests(run):
	tests = list(run_no_tests())
	run = run.split(",")
	
	for test in run:
		test = test.strip().lower()
		tests[test_dict[test]] = "1"
	return "".join(tests)

def noruntests(norun):
	tests = list(run_all_tests())
	norun = norun.split(",")
	
	for test in norun:
		test = test.strip().lower()
		tests[test_dict[test]] = "0"
	return "".join(tests)

#used to get resources with pyinstaller onefile
def resource_path(relative_path, try_temp_path=True):
	""" Get absolute path to resource, works for dev and for PyInstaller """
	if try_temp_path:
		try:
			# PyInstaller creates a temp folder and stores path in _MEIPASS
			base_path = sys._MEIPASS
		except Exception:
			base_path = os.path.abspath(".")
	else:
		base_path = os.path.abspath(".")
		
	return os.path.join(base_path, relative_path)

#fixes errors with unicode to ascii
def convert_to_string(value):
	try:
		if isinstance(value, basestring):
			return value.encode('ascii', 'ignore')
		else:
			return str(value)
	except:
		return ""

#works with the common types of registry keys
def printReg(hive, value, type, key, outFile, objRegistry):
	if type == _winreg.REG_SZ:
		result,reg_value = objRegistry.GetStringValue(hDefKey=hive,sSubKeyName=key,sValueName=value)
	elif type == _winreg.REG_EXPAND_SZ:
		result,reg_value = objRegistry.GetExpandedStringValue(hDefKey=hive,sSubKeyName=key,sValueName=value)
	elif type == _winreg.REG_BINARY:
		result,reg_value = objRegistry.GetBinaryValue(hDefKey=hive,sSubKeyName=key,sValueName=value)
		r_value = ""
		if result == 0:
			for decimal in reg_value:
				r_value += "%0.2X" % decimal
		reg_value = "[BINARY DATA] " + r_value
	elif type == _winreg.REG_DWORD:
		result,reg_value = objRegistry.GetDWORDValue(hDefKey=hive,sSubKeyName=key,sValueName=value)
	elif type == _winreg.REG_MULTI_SZ:
		result,reg_value = objRegistry.GetMultiStringValue(hDefKey=hive,sSubKeyName=key,sValueName=value)
	else:
		reg_value = ""
	
	if reg_value == None:
		reg_value = ""
	
	reg_value = convert_to_string(reg_value)
	outFile.write(key.replace(","," ") + "," + value.replace(","," ") + "," + reg_value.replace(","," ") + "\n")

#convert windows datetime to nicely formatted date
def convertDate(date):
	if date == None or len(date) < 14:
		return ""
		
	year = date[0:4]
	month = date[4:6]
	day = date[6:8]
	hour = date[8:10]
	minute = date[10:12]
	second = date[12:14]
	fullDate = year + "/" + month + "/" + day + " " + hour + ":" + minute + ":" + second
	
	if "********" in date:
		fullDate = hour + ":" + minute + ":" + second
		if "+" in date:
			offset = int(date[date.find("+")+1:])
			pdate = datetime.datetime.strptime(fullDate, "%H:%M:%S") - datetime.timedelta(minutes=offset)
			fullDate = datetime.datetime.strftime(pdate, "%H:%M:%S")
		elif "-" in date:
			offset = int(date[date.find("-")+1:])
			pdate = datetime.datetime.strptime(fullDate, "%H:%M:%S") + datetime.timedelta(minutes=offset)
			fullDate = datetime.datetime.strftime(pdate, "%H:%M:%S")
		return fullDate
		
	if "+" in date:
		offset = int(date[date.find("+")+1:])
		pdate = datetime.datetime.strptime(fullDate, "%Y/%m/%d %H:%M:%S") - datetime.timedelta(minutes=offset)
		fullDate = datetime.datetime.strftime(pdate, "%Y/%m/%d %H:%M:%S")
	elif "-" in date:
		offset = int(date[date.find("-")+1:])
		pdate = datetime.datetime.strptime(fullDate, "%Y/%m/%d %H:%M:%S") + datetime.timedelta(minutes=offset)
		fullDate = datetime.datetime.strftime(pdate, "%Y/%m/%d %H:%M:%S")
	
	return fullDate

#determine boolean value of string representation
#used to convert 1's and 0's passed in through test parameter to True/False values
def str2bool(v):
	return v.lower() in ("1", "yes", "true", "t")
	
def getDomainName():
	try:
		#get the current computer's (domain controller) domain
		objWMIService = wmi.WMI(computer=".")
		domainResults = objWMIService.ExecQuery("Select Domain from Win32_ComputerSystem")
		domainName = ""
		for result in domainResults:
			domainName = result.Domain
			return domainName
	except:
		return ""

def enumerateOUs():
	try:
		ouList = []
		domainName = getDomainName()
			
		if domainName:
			domainSplit = domainName.split(".")
			domain = ""
			for d in domainSplit:
				if domain:
					domain += ","
				domain += "DC="+d
			ouList.append("LDAP://CN=Computers,"+domain) #because people like not having organizational units and wonder why the "Computers" CN isn't listed even though it is not an organization unit but the lack thereof
			
		for OU in active_directory.search(objectCategory='organizationalUnit'):
			ouList.append(str(OU))
		
		return ouList
	except Exception as ex:
		return ["Error getting OU list. Are you sure this is a domain controller?",str(ex)]