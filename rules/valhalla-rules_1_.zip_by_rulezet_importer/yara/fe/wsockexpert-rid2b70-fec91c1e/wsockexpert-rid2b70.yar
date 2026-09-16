rule WSockExpert_RID2B70 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file WSockExpert_RID2B70.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:06:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "OpenProcessCmdExecute!" fullword ascii
      $s2 = "http://www.hackp.com" fullword ascii
      $s3 = "'%s' is not a valid time!'%s' is not a valid date and time" fullword wide
      $s4 = "SaveSelectedFilterCmdExecute" fullword ascii
      $s5 = "PasswordChar@" fullword ascii
      $s6 = "WSockHook.DLL" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 2500KB and 4 of them
}