rule APT_Lazarus_RAT_Jun18_2_RID2F03 : APT DEMO EXE FILE G0032 NK {
   meta:
      description = "Detects Lazarus Group RAT"
      author = "Florian Roth"
      reference = "https://twitter.com/DrunkBinary/status/1002587521073721346"
      date = "2018-06-01 11:39:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "e6096fb512a6d32a693491f24e67d772f7103805ad407dc37065cebd1962a547"
      tags = "APT, DEMO, EXE, FILE, G0032, NK"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\\KB\\Release\\" ascii
      $s3 = "KB, Version 1.0" fullword wide
      $s4 = "TODO: (c) <Company name>.  All rights reserved." fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 5000KB and 2 of them
}