rule FourElementSword_PowerShell_Start_RID3457 : DEMO MAL SCRIPT T1059_001 {
   meta:
      description = "Detects FourElementSword Malware"
      author = "Florian Roth"
      reference = "not set"
      date = "2016-03-26 15:26:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, MAL, SCRIPT, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "start /min powershell C:\\\\ProgramData\\\\wget.exe" ascii
      $s1 = "start /min powershell C:\\\\ProgramData\\\\iuso.exe" fullword ascii
   condition: 
      1 of them
}