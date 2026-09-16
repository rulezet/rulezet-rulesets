rule NtGodMode_RID2A72 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file NtGodMode_RID2A72.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 06:01:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "to HOST!" fullword ascii
      $s1 = "SS.EXE" fullword ascii
      $s5 = "lstrlen0" fullword ascii
      $s6 = "Virtual" fullword ascii
      $s19 = "RtlUnw" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 45KB and all of them
}