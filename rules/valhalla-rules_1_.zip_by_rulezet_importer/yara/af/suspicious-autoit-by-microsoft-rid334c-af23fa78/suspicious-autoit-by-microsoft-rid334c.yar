rule Suspicious_AutoIt_by_Microsoft_RID334C : DEMO EXE FILE SCRIPT SUSP {
   meta:
      description = "Detects a AutoIt script with Microsoft identification"
      author = "Florian Roth"
      reference = "Internal Research - VT"
      date = "2017-12-14 14:41:51"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c0cbcc598d4e8b501aa0bd92115b4c68ccda0993ca0c6ce19edd2e04416b6213"
      tags = "DEMO, EXE, FILE, SCRIPT, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Microsoft Corporation. All rights reserved" fullword wide
      $s2 = "AutoIt" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and all of them
}