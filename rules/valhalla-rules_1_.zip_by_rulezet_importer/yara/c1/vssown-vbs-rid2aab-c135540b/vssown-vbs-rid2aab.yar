rule VSSown_VBS_RID2AAB : DEMO HKTL SCRIPT T1047 {
   meta:
      description = "Detects VSSown.vbs script - used to export shadow copy elements like NTDS to take away and crack elsewhere"
      author = "Florian Roth"
      reference = "-"
      date = "2015-10-01 07:36:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, SCRIPT, T1047"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Select * from Win32_Service Where Name ='VSS'" ascii
      $s1 = "Select * From Win32_ShadowCopy" ascii
      $s2 = "cmd /C mklink /D " ascii
      $s3 = "ClientAccessible" ascii
      $s4 = "WScript.Shell" ascii
      $s5 = "Win32_Process" ascii
   condition: 
      all of them
}