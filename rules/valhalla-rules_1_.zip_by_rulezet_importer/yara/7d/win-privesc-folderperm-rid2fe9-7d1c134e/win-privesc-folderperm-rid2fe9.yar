rule Win_PrivEsc_folderperm_RID2FE9 : DEMO HKTL SCRIPT T1059_001 T1068 {
   meta:
      description = "Detects a tool that can be used for privilege escalation - file folderperm.ps1"
      author = "Florian Roth"
      reference = "http://www.greyhathacker.net/?p=738"
      date = "2016-06-02 12:17:21"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "1aa87df34826b1081c40bb4b702750587b32d717ea6df3c29715eb7fc04db755"
      tags = "DEMO, HKTL, SCRIPT, T1059_001, T1068"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "# powershell.exe -executionpolicy bypass -file folderperm.ps1" fullword ascii
      $x2 = "Write-Host \"[i] Dummy test file used to test access was not outputted:\" $filetocopy" fullword ascii
      $x3 = "Write-Host -foregroundColor Red \"      Access denied :\" $myarray[$i] " fullword ascii
   condition: 
      1 of them
}