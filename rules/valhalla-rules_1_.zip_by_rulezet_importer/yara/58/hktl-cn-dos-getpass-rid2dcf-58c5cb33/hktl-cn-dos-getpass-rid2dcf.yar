rule HKTL_CN_Dos_GetPass_RID2DCF : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file GetPass.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 10:47:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-06"
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "GetLogonS" ascii
      $s3 = "/showthread.php?t=156643" ascii
      $s8 = "To Run As Administ" ascii
      $s18 = "EnableDebugPrivileg" fullword ascii
      $s19 = "sedebugnameValue" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 890KB and all of them
}