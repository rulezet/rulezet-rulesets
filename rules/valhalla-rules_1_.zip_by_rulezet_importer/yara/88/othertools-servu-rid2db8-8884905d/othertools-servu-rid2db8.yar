rule OtherTools_servu_RID2DB8 : CHINA DEMO FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file svu.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 10:43:51"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "MZKERNEL32.DLL" fullword ascii
      $s1 = "UpackByDwing@" fullword ascii
      $s2 = "GetProcAddress" fullword ascii
      $s3 = "WriteFile" fullword ascii
   condition: 
      uint32 ( 0 ) == 0x454b5a4d and $s0 at 0 and filesize < 50KB and all of them
}