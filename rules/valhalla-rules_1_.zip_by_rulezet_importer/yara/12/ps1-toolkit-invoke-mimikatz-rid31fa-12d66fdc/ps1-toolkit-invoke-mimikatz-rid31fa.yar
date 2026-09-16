rule ps1_toolkit_Invoke_Mimikatz_RID31FA : DEMO FILE HKTL S0002 SCRIPT T1003 T1059_001 T1134_005 T1550_002 T1550_003 {
   meta:
      description = "Semiautomatically generated YARA rule - file Invoke-Mimikatz.ps1"
      author = "Florian Roth"
      reference = "https://github.com/vysec/ps1-toolkit"
      date = "2016-09-04 13:45:31"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "5c31a2e3887662467cfcb0ac37e681f1d9b0f135e6dfff010aae26587e03d8c8"
      tags = "DEMO, FILE, HKTL, S0002, SCRIPT, T1003, T1059_001, T1134_005, T1550_002, T1550_003"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Get-ProcAddress kernel32.dll WriteProcessMemory" fullword ascii
      $s2 = "ps | where { $_.Name -eq $ProcName } | select ProcessName, Id, SessionId" fullword ascii
      $s3 = "privilege::debug exit" ascii
      $s4 = "Get-ProcAddress Advapi32.dll AdjustTokenPrivileges" fullword ascii
      $s5 = "Invoke-Mimikatz -DumpCreds" fullword ascii
      $s6 = "| Add-Member -MemberType NoteProperty -Name IMAGE_FILE_EXECUTABLE_IMAGE -Value 0x0002" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0xbbef and filesize < 10000KB and 1 of them ) or ( 3 of them )
}