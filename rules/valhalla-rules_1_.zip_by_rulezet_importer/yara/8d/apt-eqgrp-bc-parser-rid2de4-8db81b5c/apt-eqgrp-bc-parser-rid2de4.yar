rule APT_EQGRP_bc_parser_RID2DE4 : APT DEMO FILE {
   meta:
      description = "Detects tool from EQGRP toolset - file bc-parser"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-15 10:51:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "879f2f1ae5d18a3a5310aeeafec22484607649644e5ecb7d8a72f0877ac19cee"
      tags = "APT, DEMO, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "*** Target may be susceptible to FALSEMOREL      ***" fullword ascii
      $s2 = "*** Target is susceptible to FALSEMOREL          ***" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x457f and 1 of them
}