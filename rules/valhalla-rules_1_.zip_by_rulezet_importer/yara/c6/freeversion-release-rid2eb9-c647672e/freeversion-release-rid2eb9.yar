rule FreeVersion_release_RID2EB9 : CHINA DEMO EXE FILE HKTL T1087_001 T1087_002 T1136 {
   meta:
      description = "Chinese Hacktool Set - file release.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 11:26:41"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL, T1087_001, T1087_002, T1136"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "-->Got WMI process Pid: %d " ascii
      $s2 = "This exploit will execute \"net user " ascii
      $s3 = "net user temp 123456 /add & net localgroup administrators temp /add" fullword ascii
      $s4 = "Running reverse shell" ascii
      $s5 = "wmiprvse.exe" fullword ascii
      $s6 = "SELECT * FROM IIsWebInfo" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 100KB and 3 of them
}