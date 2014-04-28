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

#standard library imports
import argparse
import errno
import os
import Queue
import sys
import tempfile
import threading
import time

#third party imports
import wmi

#CIS imports
from modules import enumerateOU
from modules import netstatAndDNS
from modules import userRegistry
from modules import fileList
from modules import systemRegistry
from modules import processes
from modules import tasks
from modules import services
from modules import serviceDLLs
from modules import localAccounts
from modules import dataExists
from modules import shimCache
from modules import userDataExists
from modules import retrieveNetstatAndDNS
from modules import support
from modules import rasGUI
from modules import directoryList

#get the number of tests available
RUN_ALL_TESTS = support.run_all_tests()
possibleTests = support.getPossibleTests()

#command line arguments with automatic -h help output
parser = argparse.ArgumentParser(description="Center for Internet Security - Enumeration and Scanning Program (CIS-ESP)")
group = parser.add_argument_group("Domain or Standalone Version", "These arguments can be used on either version of the scripts. A GUI will automatically display if no arguments are given.")
group.add_argument("-o", "--output", metavar="DIR", help="Path to store output. Must not have trailing slash. Example: \"C:\My Folder\".")
domainGroup = parser.add_argument_group("Domain Version Only", "These arguments will not have any affect on the standalone version. If LDAP path is not specified, it is assumed you are running the standalone version. If LDAP path is specified, it is assumed you are running the domain version.")
mutexDomainGroup = domainGroup.add_mutually_exclusive_group()
mutexDomainGroup.add_argument("-l", "--ldap", metavar="LDAP", help="Case sensitive LDAP path to OU. Example: \"LDAP://OU=\"Ball Room\",DC=Domain,DC=local\". This will enumerate all sub-OU's as well.")
mutexDomainGroup.add_argument("-i", "--hosts", metavar="HOSTSFILE", help="Specify the hosts file to skip enumerating an OU. Example: \"hosts.txt\".")
mutexDomainGroup.add_argument("-I", "--ous", metavar="OULISTFILE", help="Specify the OU list file to enumerate multiple separated OU's. Example: \"ous.txt\".")
domainGroup.add_argument("-n", "--name", metavar="NAME", help="One word conventional name for scan. Example: \"HR\".")
domainGroup.add_argument("-x", "--threads", metavar="THREADS", help="Number of threads to use. Use more than one at your own risk.")
testGroup = parser.add_argument_group("Run Tests", "Select which tests to run or not to run. Choose only one option --run, --norun, or --tests. The possible tests for --run and --norun are: " + possibleTests + ". If none of these options is chosen, all tests are run.")
mutexTestGroup = testGroup.add_mutually_exclusive_group()
mutexTestGroup.add_argument("--run", metavar="TEST1,TEST2,...", help="List the tests you want to run. Example: \"--run UserRegistry,SystemRegistry\" will run only the user and system registry modules.")
mutexTestGroup.add_argument("--norun", metavar="TEST1,TEST2,...", help="List the tests you don't want to run. Example: \"--norun DataExists,Processes,Tasks\" will run all modules except data exists, processes, and tasks.")
mutexTestGroup.add_argument("--tests", metavar="BITSTRING", help="1 or 0 for run or don't run test. Must have exactly " + str(len(RUN_ALL_TESTS)) + " digits (the number of possible tests).")
otherOptionsGroup = parser.add_argument_group("Other Options", "Additional options that you can use.")
otherOptionsGroup.add_argument("--listous", action="store_true", help="If you want to enumerate the OUs without using the GUI or dsquery.")
args = parser.parse_args()

#get any user input for the appropriate parameters
doListOUs = args.listous
if doListOUs:
	ouList = support.enumerateOUs()
	for ou in ouList:
		print ou
	sys.exit(0)

workPath = args.output
ldapPath = args.ldap
inputHosts = args.hosts
inputOUs = args.ous
scanName = args.name
tests = args.tests
threads = args.threads
run = args.run
norun = args.norun

currentPath = os.path.abspath(".")
numThreads = 1
isStandalone = False

#check if there are arguments
#if no arguments, prompt gui
if len(sys.argv) < 2:
	scanName,workPath,ldapPath,tests,numThreads = rasGUI.showGUI()

#ldap path is required for domain version
#if no ldap path, use standalone
#if ldap path, use domain
if not ldapPath and not inputHosts and not inputOUs:
	isStandalone = True

#use user input for scan name if available, otherwise set to default
if not scanName:
	scanName = "scan"

#use user input for output directory if available, otherwise set to directory from which script is running
if not workPath:
	workPath = currentPath

#use user input for tests if available and valid, otherwise set to run all tests
if not tests or len(tests) != len(RUN_ALL_TESTS) or not tests.isdigit():
	if run:
		tests = support.runtests(run)
	elif norun:
		tests = support.noruntests(norun)
	else:
		tests = RUN_ALL_TESTS

#use user input for number of threads if available, otherwise set to default of 1
if not threads or not threads.isdigit() or int(threads) < 1:
	numThreads = 1
else:
	numThreads = int(threads)

currentTimestamp = time.strftime("%Y%m%d%H%M%S")

if not isStandalone:
	domainName = support.getDomainName()

	#work path is where data is saved
	workPath = workPath + "\\" + currentTimestamp + "-" + scanName + "-" + domainName
else:
	computerName = os.environ['COMPUTERNAME']
	#work path is where data is saved
	workPath = workPath + "\\" + currentTimestamp + "-" + computerName

#create the working directory
try:
	os.makedirs(workPath)
except OSError as exception:
	if exception.errno != errno.EEXIST:
		raise

#print starting scan details
print "\n"

if not isStandalone:
	if inputHosts:
		print "Reading from hosts file"
	elif inputOUs:
		print "Reading from OU list file"
	else:
		print "Enumerating Domain: " + domainName
		print "Parsing computer objects from: " + ldapPath

print "Saving output in: " + workPath

#the scan path is used to find config files
#scanPath = currentPath + "\\config"

if not isStandalone:
	if inputHosts:
		hostList = open(inputHosts, "r").readlines()
		finalHostsFile = open(workPath + "\\FINAL-" + scanName + "-hosts.txt", "w")
	
		for host in hostList:
			finalHostsFile.write(host)
			
		finalHostsFile.close()
	else:
		if inputOUs:
			ouList = open(inputOUs, "r").readlines()
			ldapPathList = []
			
			for ou in ouList:
				ldapPathList.append(ou.replace("\n",""))
		elif ldapPath:
			ldapPathList = [ldapPath]
				
		#enumerate the hosts in the given LDAP path(s) and save to hosts file
		if ldapPathList:
			enumerateOU.enumerateOU(workPath,ldapPathList,scanName)

#create error log and time tracking files
errLog = open(workPath + "\\errlog.txt", "w")
timeFile = open(workPath + "\\timefile.txt", "w")
#write the current time to the file for start of scan
timeFile.write("Start: " + time.strftime("%m/%d/%Y %H:%M:%S") + "\n")

#extract which tests to run
runNetstatDNS = support.str2bool(tests[0])
runUserRegistry = support.str2bool(tests[1])
runFileList = support.str2bool(tests[2])
runSystemRegistry = support.str2bool(tests[3])
runProcesses = support.str2bool(tests[4])
runTasks = support.str2bool(tests[5])
runServices = support.str2bool(tests[6])
runServiceDLLs = support.str2bool(tests[7])
runLocalAccounts = support.str2bool(tests[8])
runDataExists = support.str2bool(tests[9])
runShimCache = support.str2bool(tests[10])
runUserDataExists = support.str2bool(tests[11])
runDirectoryList = support.str2bool(tests[12])
runShellbags = support.str2bool(tests[13])

#create temporary files for the extra indicator lists
tmpSystemRegFile = tempfile.TemporaryFile("w+")
tmpUserRegFile = tempfile.TemporaryFile("w+")
tmpFileListFile = tempfile.TemporaryFile("w+")
tmpDataExistsFile = tempfile.TemporaryFile("w+")
tmpUserDataExistsFile = tempfile.TemporaryFile("w+")
tmpDirectoryListFile = tempfile.TemporaryFile("w+")

extraConfigDir = currentPath + "\\CIS-Config"
if os.path.isdir(extraConfigDir):
	try:
		_,_,filenames = os.walk(extraConfigDir).next()
		
		for filename in filenames:
			with open(extraConfigDir + "\\" + filename, "r") as f:
				categories = f.read().split("##")
				for lines in categories:
					lines = lines.strip()
					if lines.startswith("SystemRegistry\n"):
						tmpSystemRegFile.write(lines[lines.find("\n"):])
					elif lines.startswith("UserRegistry\n"):
						tmpUserRegFile.write(lines[lines.find("\n"):])
					elif lines.startswith("FileList\n"):
						tmpFileListFile.write(lines[lines.find("\n"):])
					elif lines.startswith("DataExists\n"):
						tmpDataExistsFile.write(lines[lines.find("\n"):])
					elif lines.startswith("UserDataExists\n"):
						tmpUserDataExistsFile.write(lines[lines.find("\n"):])
					elif lines.startswith("DirectoryList\n"):
						tmpDirectoryListFile.write(lines[lines.find("\n"):])
	except:
		pass

tmpSystemRegFile.seek(0)
tmpSystemReg = tmpSystemRegFile.readlines()

tmpUserRegFile.seek(0)
tmpUserReg = tmpUserRegFile.readlines()

tmpFileListFile.seek(0)
tmpFileList = tmpFileListFile.readlines()

tmpDataExistsFile.seek(0)
tmpDataExists = tmpDataExistsFile.readlines()

tmpUserDataExistsFile.seek(0)
tmpUserDataExists = tmpUserDataExistsFile.readlines()

tmpDirectoryListFile.seek(0)
tmpDirectoryList = tmpDirectoryListFile.readlines()

#this method is called for each host in the domain version
#it runs all the specified tests on that host and saves the output in a per host directory in the working path directory
#if the computer can't be reached, it is added to the error log with the exception/error
def runScans(host, domainName):
	print "Attempting to connect to: " + host
	
	if domainName != None:
		computerName = host + "." + domainName
	else:
		computerName = host
	
	#try to connect using wmi
	try:
		objWMIService = wmi.WMI(computer=computerName)
		objProcWMI = objWMIService.Win32_Process
		objRegistry = wmi.Registry(computer=computerName)
		objProcWMI2 = wmi.WMI(computer=computerName,privileges=("Backup","Restore")).Win32_Process
	except Exception as ex: #on fail
		print ex
		errLog.write(host + " - " + str(ex) + "\n") #write it to the error log
		return #stop scan of this host now
	
	#per host directory
	if domainName != None:
		hostPath = workPath + "\\" + host
		
	else:
		hostPath = workPath
		
	#create the host directory
	try:
		os.makedirs(hostPath)
	except OSError as exception:
		if exception.errno != errno.EEXIST:
			raise
	
	print "Starting scan: " + computerName
	
	if domainName != None:
		#write a per host error and time file to track scan duration
		hostErrorLog = open(hostPath + "\\error.txt", "w")
		hostTimeFile = open(hostPath + "\\timefile.txt", "w")
		hostTimeFile.write("Start: " + time.strftime("%m/%d/%Y %H:%M:%S") + "\n")
	else:
		hostErrorLog = errLog
	
	if runNetstatDNS:
		netstatAndDNS.getNetstatAndDNS(computerName,hostErrorLog,objProcWMI)
		
	if runUserRegistry or runShellbags:
		userRegistry.getUserRegistry(computerName,objRegistry,objProcWMI2,hostPath,tmpUserReg,runUserRegistry,runShellbags)
		
	if runFileList:
		fileList.getFileList(computerName,objWMIService,hostPath,tmpFileList)
		
	if runSystemRegistry:
		systemRegistry.getSystemRegistry(computerName,objRegistry,hostPath,tmpSystemReg)
		
	if runProcesses:
		processes.getProcesses(computerName,objWMIService,hostPath)
		
	if runTasks:
		tasks.getTasks(computerName,objWMIService,hostPath)
		
	if runServices:
		services.getServices(computerName,objWMIService,hostPath)
		
	if runServiceDLLs:
		serviceDLLs.getServiceDLLs(computerName,objRegistry,hostPath)
		
	if runLocalAccounts:
		localAccounts.getLocalAccounts(computerName,objWMIService,hostPath)

	if runDataExists:
		dataExists.getDataExists(computerName,objWMIService,hostPath,tmpDataExists)
		
	if runShimCache:
		shimCache.getShimCache(computerName,objRegistry,hostPath)
		
	if runUserDataExists:
		userDataExists.getUserDataExists(computerName,objWMIService,objRegistry,hostPath,tmpUserDataExists)
		
	if runDirectoryList:
		directoryList.getDirectoryList(computerName,objWMIService,hostPath,tmpDirectoryList)
		
	if runNetstatDNS:
		retrieveNetstatAndDNS.retrieveNetstatAndDNS(computerName,hostErrorLog,objWMIService,objProcWMI,hostPath)
		
	if domainName != None:
		hostErrorLog.close()
		hostDoneFile = open(hostPath + "\\_done.txt", "w")
		hostDoneFile.close()
		#end time for this particular host
		hostTimeFile.write("End: " + time.strftime("%m/%d/%Y %H:%M:%S") + "\n")
		hostTimeFile.close()
	print "Finished scan: " + computerName

#worker thread
def worker(q):
	#importing pythoncom and using CoInitialize() are required to execute WMI commands in threads
	import pythoncom 
	pythoncom.CoInitialize()
	while True:
		host,domainName = q.get() #get the next host from the queue
		runScans(host,domainName) #run the designated scans
		q.task_done() #remove the host from the queue

if not isStandalone:
	#hostsFile = open(workPath + "\\hosts.txt", "r")
	#final hosts file ensures uniqueness of each host in list
	hostsFile = open(workPath + "\\FINAL-" + scanName + "-hosts.txt", "r")
	hostList = hostsFile.readlines()
	queue = Queue.Queue()

	#create the number of threads as specified by the input arguments
	for i in range(numThreads):
		 t = threading.Thread(target=worker, args=(queue,))
		 t.daemon = True #set as background thread that terminates when the overall program terminates
		 t.start()

	#add hosts to the queue
	for host in hostList:
		host = host.replace("\n","")
		queue.put((host,domainName))
	
	queue.join() #wait for queue to be empty
	hostsFile.close()
else:
	runScans(computerName,None)

doneFile = open(workPath + "\\done.txt", "w")
doneFile.close()
#write the current time to the timefile indicating the end of scan
timeFile.write("End: " + time.strftime("%m/%d/%Y %H:%M:%S") + "\n")
timeFile.close()
