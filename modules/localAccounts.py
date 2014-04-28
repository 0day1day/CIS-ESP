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

def getLocalAccounts(computerName,objWMIService,hostPath):
	print computerName + " - checking local accounts"
	outFile = open(hostPath + "\ACCOUNTS-" + computerName + ".csv", "w")
	outFile.write("account_type,caption,description,disabled,domain,full_name,local_account,lockout,install_date,name,password_changeable,password_expires,password_required,sid,sid_type,status\n")
	
	query = "Select DomainRole From Win32_ComputerSystem"
	domainRoles = objWMIService.ExecQuery(query)
	
	for domainRole in domainRoles:
		if domainRole.DomainRole == 4 or domainRole.domainRole == 5:
			outFile.write("This is a domain controller. The local accounts cannot be accessed\n")
		else:
			query = "Select InstallDate,AccountType,Caption,Description,Disabled,Domain,FullName,LocalAccount,Lockout,Name,PasswordChangeable,PasswordExpires,PasswordRequired,SID,SIDType,Status from Win32_UserAccount Where LocalAccount = True"
			accounts = objWMIService.ExecQuery(query)
			
			for account in accounts:
				accountType = support.convert_to_string(account.AccountType)
				accountCaption = support.convert_to_string(account.Caption)
				accountDescription = support.convert_to_string(account.Description)
				
				accountDisabled = support.convert_to_string(account.Disabled)
				if accountDisabled.upper() == "TRUE":
					accountDisabled = "1"
				else:
					accountDisabled = "0"
					
				accountDomain = support.convert_to_string(account.Domain)
				accountFullName = support.convert_to_string(account.FullName)
				
				accountLocalAccount = support.convert_to_string(account.LocalAccount)
				if accountLocalAccount.upper() == "TRUE":
					accountLocalAccount = "1"
				else:
					accountLocalAccount = "0"
					
				accountLockout = support.convert_to_string(account.Lockout)
				if accountLockout.upper() == "TRUE":
					accountLockout = "1"
				else:
					accountLockout = "0"
					
				accountInstallDate = support.convertDate(support.convert_to_string(account.InstallDate))
					
				accountName = support.convert_to_string(account.Name)
				
				accountPasswordChangeable = support.convert_to_string(account.PasswordChangeable)
				if accountPasswordChangeable.upper() == "TRUE":
					accountPasswordChangeable = "1"
				else:
					accountPasswordChangeable = "0"
					
				accountPasswordExpires = support.convert_to_string(account.PasswordExpires)
				if accountPasswordExpires.upper() == "TRUE":
					accountPasswordExpires = "1"
				else:
					accountPasswordExpires = "0"
					
				accountPasswordRequired = support.convert_to_string(account.PasswordRequired)
				if accountPasswordRequired.upper() == "TRUE":
					accountPasswordRequired = "1"
				else:
					accountPasswordRequired = "0"
					
				accountSID = support.convert_to_string(account.SID)
				accountSIDType = support.convert_to_string(account.SIDType)
				accountStatus = support.convert_to_string(account.Status)
				
				outFile.write(accountType.replace(","," ") + "," + accountCaption.replace(","," ") + "," + accountDescription.replace(","," ") + "," + accountDisabled + "," + 
					accountDomain.replace(","," ") + "," + accountFullName.replace(","," ") + "," + accountLocalAccount + "," + accountLockout + "," + 
					accountInstallDate + "," + accountName.replace(","," ") + "," + accountPasswordChangeable + "," + accountPasswordExpires + "," + 
					accountPasswordRequired + "," + accountSID.replace(","," ") + "," + accountSIDType.replace(","," ") + "," + accountStatus.replace(","," ") + "\n")
					
		outFile.close()
		break	
	
	outFile = open(hostPath + "\LOCALADMINS-" + computerName + ".csv", "w")
	outFile.write("domain,user")
	query = "select * from Win32_GroupUser where GroupComponent = \"Win32_Group.Domain='" + computerName + "',Name='Administrators'\""
	admins = objWMIService.ExecQuery(query)
	
	for admin in admins:
		partComponent = support.convert_to_string(admin.PartComponent)
		domainPos = partComponent.find("Win32_UserAccount.Domain=") + len("Win32_UserAccount.Domain=")
		
		if domainPos <= len("Win32_UserAccount.Domain="):
			domainPos = partComponent.find("Win32_Group.Domain=") + len("Win32_Group.Domain=")
			
		namePos = partComponent.find(",Name=",domainPos)
		
		if domainPos <= len("Win32_Group.Domain="):
			domain = ""
		else:
			domain = partComponent[domainPos+1:namePos-1] #remove quotes
			
		namePos += len(",Name=")
		
		if namePos <= len(",Name="):
			name = ""
		else:
			name = partComponent[namePos+1:-1] #remove quotes
		
		
		outFile.write(domain + "," + name + "\n")
		
	outFile.close()
