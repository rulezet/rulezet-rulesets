rule Armitage_msfconsole_RID2ED3 : DEMO HKTL {
   meta:
      description = "Detects Armitage component"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-12-24 11:31:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-08-18"
      hash1 = "662ba75c7ed5ac55a898f480ed2555d47d127a2d96424324b02724b3b2c95b6a"
      tags = "DEMO, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\\umeterpreter\\u >" ascii
      $s3 = "^meterpreter >" fullword ascii
      $s11 = "\\umsf\\u>" ascii
   condition: 
      filesize < 1KB and 2 of them
}