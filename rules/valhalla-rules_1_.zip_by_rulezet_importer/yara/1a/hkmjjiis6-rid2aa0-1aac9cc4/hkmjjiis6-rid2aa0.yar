rule hkmjjiis6_RID2AA0 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file hkmjjiis6_RID2AA0.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 07:18:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "comspec" fullword ascii
      $s2 = "user32.dlly" ascii
      $s3 = "runtime error" ascii
      $s4 = "WinSta0\\Defau" ascii
      $s5 = "AppIDFlags" fullword ascii
      $s6 = "GetLag" fullword ascii
      $s7 = "* FROM IIsWebInfo" ascii
      $s8 = "wmiprvse.exe" ascii
      $s9 = "LookupAcc" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 70KB and all of them
}