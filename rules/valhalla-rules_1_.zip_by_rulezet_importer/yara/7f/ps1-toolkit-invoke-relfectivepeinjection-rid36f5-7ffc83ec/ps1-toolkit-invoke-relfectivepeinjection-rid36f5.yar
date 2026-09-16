rule ps1_toolkit_Invoke_RelfectivePEInjection_RID36F5 : DEMO FILE HKTL SCRIPT T1055_002 T1059_001 {
   meta:
      description = "Semiautomatically generated YARA rule - file Invoke-RelfectivePEInjection.ps1"
      author = "Florian Roth"
      reference = "https://github.com/vysec/ps1-toolkit"
      date = "2016-09-04 17:18:01"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "510b345f821f93c1df5f90ac89ad91fcd0f287ebdabec6c662b716ec9fddb03a"
      tags = "DEMO, FILE, HKTL, SCRIPT, T1055_002, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Invoke-ReflectivePEInjection -PEBytes $PEBytes -FuncReturnType WString -ComputerName (Get-Content targetlist.txt)" fullword ascii
      $x2 = "Invoke-ReflectivePEInjection -PEBytes $PEBytes -FuncReturnType WString -ComputerName Target.local" fullword ascii
      $x3 = "} = Get-ProcAddress Advapi32.dll OpenThreadToken" ascii
      $x4 = "Invoke-ReflectivePEInjection -PEBytes $PEBytes -ProcName lsass -ComputerName Target.Local" fullword ascii
      $s5 = "$PEBytes = [IO.File]::ReadAllBytes('DemoDLL_RemoteProcess.dll')" fullword ascii
      $s6 = "= Get-ProcAddress Advapi32.dll AdjustTokenPrivileges" ascii
   condition: 
      ( uint16 ( 0 ) == 0xbbef and filesize < 700KB and 2 of them ) or ( all of them )
}