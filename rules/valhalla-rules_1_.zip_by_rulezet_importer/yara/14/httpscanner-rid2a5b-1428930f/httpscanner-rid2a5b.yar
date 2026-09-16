rule HTTPSCANNER_RID2A5B : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file HTTPSCANNER_RID2A5B.EXE"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 05:23:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "HttpScanner.exe" fullword wide
      $s2 = "HttpScanner" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 3500KB and all of them
}