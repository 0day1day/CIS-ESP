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

def getTasks(computerName,objWMIService,hostPath):
	print computerName + " - checking tasks"
	outFile = open(hostPath + "\TASKS-" + computerName + ".csv", "w")
	outFile.write("command,days_of_month,days_of_week,description,elapsed_time,install_date,interact_with_desktop,job_id,job_status,name,notify,owner,priority,run_repeatedly,start_time,status,time_submitted,until_time\n")
	
	tasks = objWMIService.ExecQuery("Select * from Win32_ScheduledJob")
	for task in tasks:
		taskCommand = support.convert_to_string(task.Command)
		
		taskDaysOfMonth = support.convert_to_string(task.DaysOfMonth)
		if taskDaysOfMonth == "None":
			taskDaysOfMonth = "NULL"
			
		taskDaysOfWeek = support.convert_to_string(task.DaysOfWeek)
		if taskDaysOfWeek == "None":
			taskDaysOfWeek = "NULL"
			
		taskDescription = support.convert_to_string(task.Description)
		
		taskElapsedTime = support.convertDate(support.convert_to_string(task.ElapsedTime))
			
		taskInstallDate = support.convertDate(support.convert_to_string(task.InstallDate))
			
		taskInteractWithDesktop = support.convert_to_string(task.InteractWithDesktop)
		if taskInteractWithDesktop.upper() == "TRUE":
			taskInteractWithDesktop = "1"
		else:
			taskInteractWithDesktop = "0"
			
		taskJobId = support.convert_to_string(task.JobId)
		taskJobStatus = support.convert_to_string(task.JobStatus)
		taskName = support.convert_to_string(task.Name)
		taskNotify = support.convert_to_string(task.Notify)
		taskOwner = support.convert_to_string(task.Owner)
		
		taskPriority = support.convert_to_string(task.Priority)
		if taskPriority == "None":
			taskPriority = "NULL"
		
		taskRunRepeatedly = support.convert_to_string(task.RunRepeatedly)
		if taskRunRepeatedly.upper() == "TRUE":
			taskRunRepeatedly = "1"
		else:
			taskRunRepeatedly = "0"
			
		taskStartTime = support.convertDate(support.convert_to_string(task.StartTime))
		
		taskStatus = support.convert_to_string(task.Status)
		
		taskTimeSubmitted = support.convertDate(support.convert_to_string(task.TimeSubmitted))
			
		taskUntilTime = support.convertDate(support.convert_to_string(task.UntilTime))
		
		outFile.write(taskCommand.replace(","," ") + "," + taskDaysOfMonth.replace(","," ") + "," + taskDaysOfWeek.replace(","," ") + "," + 
			taskDescription.replace(","," ") + "," + taskElapsedTime.replace(","," ") + "," + taskInstallDate.replace(","," ") + "," + 
			taskInteractWithDesktop.replace(","," ") + "," + taskJobId.replace(","," ") + "," + taskJobStatus.replace(","," ") + "," + 
			taskName.replace(","," ") + "," + taskNotify.replace(","," ") + "," + taskOwner.replace(","," ") + "," + 
			taskPriority.replace(","," ") + "," + taskRunRepeatedly.replace(","," ") + "," + taskStartTime.replace(","," ") + "," + 
			taskStatus.replace(","," ") + "," + taskTimeSubmitted.replace(","," ") + "," + taskUntilTime.replace(","," ") + "\n")
	
	outFile.close()
