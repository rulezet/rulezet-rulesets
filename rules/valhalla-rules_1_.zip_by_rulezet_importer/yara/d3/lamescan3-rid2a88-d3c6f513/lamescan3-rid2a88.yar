rule lamescan3_RID2A88 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file lamescan3_RID2A88.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 06:38:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "dic\\loginlist.txt" fullword ascii
      $s2 = "Radmin.exe" fullword ascii
      $s3 = "lamescan3_RID2A88.pdf!" fullword ascii
      $s4 = "dic\\passlist.txt" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 3740KB and all of them
}