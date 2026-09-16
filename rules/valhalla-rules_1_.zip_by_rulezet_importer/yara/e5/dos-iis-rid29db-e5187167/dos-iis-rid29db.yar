rule Dos_iis_RID29DB : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file iis.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 01:50:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "comspec" fullword ascii
      $s2 = "program terming" fullword ascii
      $s3 = "WinSta0\\Defau" fullword ascii
      $s4 = "* FROM IIsWebInfo" ascii
      $s5 = "www.icehack." ascii
      $s6 = "wmiprvse.exe" fullword ascii
      $s7 = "Pid: %d" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 70KB and all of them
}