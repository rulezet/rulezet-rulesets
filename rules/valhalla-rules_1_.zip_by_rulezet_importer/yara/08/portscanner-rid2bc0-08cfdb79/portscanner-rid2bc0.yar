rule portscanner_RID2BC0 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file portscanner_RID2BC0.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:19:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "PortListfNo" fullword ascii
      $s1 = ".533.net" fullword ascii
      $s2 = "CRTDLL.DLL" fullword ascii
      $s3 = "exitfc" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 25KB and all of them
}