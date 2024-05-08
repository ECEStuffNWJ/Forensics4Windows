# setup audit trail
md C:\research
Start-Transcript –Path C:\research\analysis.log

# users not logged on (for suspect anlaysis)
get-winevent -FilterHashTable @{LogName=’Security’; StartTime=’6/27/2012 12:00:00am’; ID=@(4624,4625,4634,4647,4648)} |
select timecreated,id

eventhashtable = @{LogName=’Security’; StartTime=’3/27/2024 12:00:00am’; ID=@(4624,4625,4634,4647,4648)};

‘workstation01’, ‘workstation02’, ‘workstation03’, ‘workstation04’ | % {
            Write “Retrieving logs for $_ at $(Get-Date)”;
            get-winevent –FilterHashTable $eventhashtable | select timecreated,id;
}

# get sessions and IDs
New-PSSession -ComputerName server
if(-not(Test-Path HKU:\))

{          
            New-PSDrive HKU Registry HKEY_USERS
}
dir HKU:\ |

Where {($_.Name -match ‘S-1-5-[0-2][0-2]-‘) -and ($_.Name -notmatch ‘_Classes’)} |

Select PSChildName |

% {
            (([ADSI] (“LDAP://<SID=” + $_.PSChildName + “>”)).userPrincipalName -split ‘@’)[0] + ” – ” + $_.PSChildName
}

# file access
# edit admin users names

‘admin03′,’admin04’ |
% {
            md “C:\research\$_”
            copy “\\server\c$\users\$_\ntuser.dat” “C:\research\$_”
}

# get net connections
Get-NetTCPConnection –State Established

# get system processes
Get-Process
Get-Process wlms | format-list *

# get windows logs and events
Get-EventLog -list
Get-EventLog -list | %{ Get-EventLog $_.Log}
Get-WinEvent -LogName "Security","System","Application"

# get computer info
Get-CimInstance -Class CIM_ComputerSystem -ComputerName localhost -ErrorAction Stop | Select-Object *

# get remote system info 
Get-CimInstance -Class CIM_ComputerSystem -ComputerName (Get-Content -Path C:\Temp\Servers.txt) -ErrorAction Stop | Select-Object * | Out-GridView

# get ADd User
Get-ADUser -Filter *
Get-ADGroup -Filter *
ForEach ($Group in (Get-ADGroup -Filter *)) { Get-ADGroupMember $Group | Select @{Label="Group";Expression={$Group.Name}},Name,SamAccountName }

# startup processes
Get-CimInstance win32_service -Filter "startmode = 'auto'"

# recently modified files
Get-ChildItem -Recurse C:\ | ? {$_.lastwritetime -gt (Get-Date).AddDays(-7)}

# run Key Persistence 
Get-ForensicRunKey -VolumeName C: | Format-List
Get-ForensicRunKey -HivePath ‘C:\Windows\System32\config\SOFTWARE’ | Format-List

# get Child Items
Get-ForensicChildItem -Path C:\
Get-ForensicChildItem
Get-ForensicChildItem -Path C:\ | Get-ForensicFileRecord

Exit-PSSession
