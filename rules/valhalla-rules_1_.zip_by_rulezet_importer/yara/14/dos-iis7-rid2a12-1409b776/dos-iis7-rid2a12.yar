rule Dos_iis7_RID2A12 : CHINA DEMO EXE FILE HKTL T1033 {
   meta:
      description = "Chinese Hacktool Set - file iis7.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 03:21:41"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL, T1033"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "\\\\localhost" fullword ascii
      $s1 = "iis.run" fullword ascii
      $s3 = ">Could not connecto %s" fullword ascii
      $s5 = "WHOAMI" ascii
      $s13 = "WinSta0\\Default" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 140KB and all of them
}