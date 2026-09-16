rule APT_EQGRP_BPATROL_2201_RID2D6B : APT DEMO FILE {
   meta:
      description = "EQGRP Toolset Firewall - file BPATROL-2201.exe"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 10:31:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "aa892750b893033eed2fedb2f4d872f79421174eb217f0c34a933c424ae66395"
      tags = "APT, DEMO, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "dumpConfig" fullword ascii
      $s2 = "getstatusHandler" fullword ascii
      $s3 = ".got_loader" fullword ascii
      $s4 = "xtractdata" fullword ascii
      $s5 = "KEEPGOING" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 40KB and all of them )
}