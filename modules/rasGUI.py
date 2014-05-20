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

from Tkinter import *
import Tkconstants
import tkFileDialog
import active_directory

from modules import support

root = Tk()

scanName = ""
outputDir = ""
ou = ""
testString = ""
numThreads = ""

versionDescriptionLabel = Label(root, text="The standalone version will run only on this system. The domain version allows you to choose an OU and run it on all live systems in that OU. The domain version requires you to be on a domain controller.")
button_opt = {'fill': Tkconstants.BOTH, 'padx': 5, 'pady': 5}

scanNameEntry = Entry(root, bd=5, width=100)

chosenOU = StringVar(root)
numThreadsEntry = Entry(root, bd=5, width=100)
outputDirVar = StringVar()
runNsDnsVar = IntVar()
runNsDnsVar.set(1)
runUserAutostartVar = IntVar()
runUserAutostartVar.set(1)
runFileListVar = IntVar()
runFileListVar.set(1)
runAutostartVar = IntVar()
runAutostartVar.set(1)
runProcVar = IntVar()
runProcVar.set(1)
runTasksVar = IntVar()
runTasksVar.set(1)
runServicesVar = IntVar()
runServicesVar.set(1)
runServiceDLLVar = IntVar()
runServiceDLLVar.set(1)
runLocalAccountsVar = IntVar()
runLocalAccountsVar.set(1)
runDataExistsVar = IntVar()
runDataExistsVar.set(1)
runShimCacheVar = IntVar()
runShimCacheVar.set(1)
runUserDataExistsVar = IntVar()
runUserDataExistsVar.set(1)
runDirectoryListVar = IntVar()
runDirectoryListVar.set(1)
runShellbagsVar = IntVar()
runShellbagsVar.set(1)
runUsbDevicesVar = IntVar()
runUsbDevicesVar.set(1)

def askdirectory():
	"""Returns a selected directoryname."""
	global outputDir
	outputDir = tkFileDialog.askdirectory()
	outputDirVar.set(outputDir)

def selectAll():
	runNsDnsVar.set(1)
	runUserAutostartVar.set(1)
	runFileListVar.set(1)
	runAutostartVar.set(1)
	runProcVar.set(1)
	runTasksVar.set(1)
	runServicesVar.set(1)
	runServiceDLLVar.set(1)
	runLocalAccountsVar.set(1)
	runDataExistsVar.set(1)
	runShimCacheVar.set(1)
	runUserDataExistsVar.set(1)
	runDirectoryListVar.set(1)
	runShellbagsVar.set(1)
	runUsbDevicesVar.set(1)

def deselectAll():
	runNsDnsVar.set(0)
	runUserAutostartVar.set(0)
	runFileListVar.set(0)
	runAutostartVar.set(0)
	runProcVar.set(0)
	runTasksVar.set(0)
	runServicesVar.set(0)
	runServiceDLLVar.set(0)
	runLocalAccountsVar.set(0)
	runDataExistsVar.set(0)
	runShimCacheVar.set(0)
	runUserDataExistsVar.set(0)
	runDirectoryListVar.set(0)
	runShellbagsVar.set(0)
	runUsbDevicesVar.set(0)

def createGUI(standalone):
	versionDescriptionLabel.pack_forget()
	standaloneButton.pack_forget()
	domainButton.pack_forget()
	
	if not standalone:
		scanNameLabel = Label(root, text="Scan Name")
		scanNameLabel.pack()
		scanNameEntry.pack()
	
	Button(text='Output Directory', command=askdirectory).pack(**button_opt)
	outputDirLabel = Label(root, textvariable=outputDirVar)
	outputDirLabel.pack()
	
	if not standalone:
		ouOptions = support.enumerateOUs()
		chosenOU.set(ouOptions[0])

		ouOptionMenu = OptionMenu(root, chosenOU, *ouOptions)
		ouOptionMenu.config(width=100)
		ouOptionMenu.pack()

	runNsDnsCheck = Checkbutton(root, text="Netstat/DNS", variable=runNsDnsVar)
	runNsDnsCheck.pack()

	runUserAutostartCheck = Checkbutton(root, text="User Registry", variable=runUserAutostartVar)
	runUserAutostartCheck.pack()

	runFileListVarCheck = Checkbutton(root, text="File List", variable=runFileListVar)
	runFileListVarCheck.pack()

	runAutostartCheck = Checkbutton(root, text="System Registry", variable=runAutostartVar)
	runAutostartCheck.pack()

	runProcCheck = Checkbutton(root, text="Process/Process Modules", variable=runProcVar)
	runProcCheck.pack()

	runTasksCheck = Checkbutton(root, text="Tasks", variable=runTasksVar)
	runTasksCheck.pack()

	runServicesCheck = Checkbutton(root, text="Services", variable=runServicesVar)
	runServicesCheck.pack()

	runServiceDLLCheck = Checkbutton(root, text="Service DLLs", variable=runServiceDLLVar)
	runServiceDLLCheck.pack()

	runLocalAccountsCheck = Checkbutton(root, text="Local Accounts/Local Admins", variable=runLocalAccountsVar)
	runLocalAccountsCheck.pack()

	runDataExistsCheck = Checkbutton(root, text="Data Exists", variable=runDataExistsVar)
	runDataExistsCheck.pack()

	runShimCacheCheck = Checkbutton(root, text="Shim Cache", variable=runShimCacheVar)
	runShimCacheCheck.pack()

	runUserDataExistsCheck = Checkbutton(root, text="User Data Exists", variable=runUserDataExistsVar)
	runUserDataExistsCheck.pack()
	
	runDirectoryListCheck = Checkbutton(root, text="Directory List", variable=runDirectoryListVar)
	runDirectoryListCheck.pack()
	
	runShellbagsCheck = Checkbutton(root, text="Shellbags", variable=runShellbagsVar)
	runShellbagsCheck.pack()
	
	runUsbDevicesCheck = Checkbutton(root, text="Shellbags", variable=runUsbDevicesVar)
	runUsbDevicesCheck.pack()
	
	Button(text='Select All', command=selectAll).pack(**button_opt)
	Button(text='Deselect All', command=deselectAll).pack(**button_opt)
	
	if not standalone:
		numThreadsLabel = Label(root, text="Number of Threads")
		numThreadsLabel.pack()
		numThreadsEntry.pack()
	
	submit = Button(root, text ="Submit", command=submitConfig)
	submit.pack()
	
	if not standalone:
		root.title("CIS Enumeration and Scanning Program - Domain Version")
	else:
		root.title("CIS Enumeration and Scanning Program - Standalone Version")

def showStandaloneGUI():
	createGUI(standalone=True)
	return

def showDomainGUI():
	createGUI(standalone=False)
	return

def submitConfig():
	global scanName
	
	try:
		scanName = scanNameEntry.get()
	except:
		pass
	
	global numThreads
	
	try:
		numThreads = numThreadsEntry.get()
	except:
		pass
	
	global ou
	
	try:
		ou = chosenOU.get()
		if ou == "Error getting OU list. Are you sure this is a domain controller?":
			ou = ""
	except:
		pass
	
	global testString
	testString = "" + str(runNsDnsVar.get()) + str(runUserAutostartVar.get()) + str(runFileListVar.get()) + \
	str(runAutostartVar.get()) + str(runProcVar.get()) + str(runTasksVar.get()) + str(runServicesVar.get()) + \
	str(runServiceDLLVar.get()) + str(runLocalAccountsVar.get()) + str(runDataExistsVar.get()) + \
	str(runShimCacheVar.get()) + str(runUserDataExistsVar.get()) + str(runDirectoryListVar.get()) + \
	str(runShellbagsVar.get() + str(runUsbDevicesVar.get()))
	root.quit()

standaloneButton = Button(text='Run Standalone Version', command=showStandaloneGUI)
domainButton = Button(text='Run Domain Version', command=showDomainGUI)	

def showGUI():
	versionDescriptionLabel.pack()
	standaloneButton.pack(**button_opt)
	domainButton.pack(**button_opt)
	root.title("CIS Enumeration and Scanning Program")
	root.mainloop()
	root.destroy()
	return (scanName,outputDir,ou,testString,numThreads)
	
	
