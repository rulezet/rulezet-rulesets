rule APT_EQGRP_morel_RID2C52 : APT DEMO EXE FILE {
   meta:
      description = "Detects tool from EQGRP toolset - file morel.exe"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-15 09:44:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a9152e67f507c9a179bb8478b58e5c71c444a5a39ae3082e04820a0613cd6d9f"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "%d - %d, %d" fullword ascii
      $s2 = "%d - %lu.%lu %d.%lu" fullword ascii
      $s3 = "%d - %d %d" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 60KB and all of them )
}