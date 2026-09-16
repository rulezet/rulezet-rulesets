rule SQLTools_RID2A12 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file SQLTools_RID2A12.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 03:21:41"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "DBN_POST" fullword wide
      $s2 = "LOADER ERROR" fullword ascii
      $s3 = "www.1285.net" fullword wide
      $s4 = "TUPFILEFORM" fullword wide
      $s5 = "DBN_DELETE" fullword wide
      $s6 = "DBINSERT" fullword wide
      $s7 = "Copyright (C) Kibosoft Corp. 2001-2006" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 2350KB and all of them
}