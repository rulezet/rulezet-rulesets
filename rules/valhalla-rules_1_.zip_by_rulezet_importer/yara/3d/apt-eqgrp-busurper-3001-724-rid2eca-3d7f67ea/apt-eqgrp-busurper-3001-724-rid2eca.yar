rule APT_EQGRP_BUSURPER_3001_724_RID2ECA : APT DEMO FILE {
   meta:
      description = "EQGRP Toolset Firewall - file BUSURPER-3001-724.exe"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 11:29:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "6b558a6b8bf3735a869365256f9f2ad2ed75ccaa0eefdc61d6274df4705e978b"
      tags = "APT, DEMO, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "IMPLANT" fullword ascii
      $s2 = "KEEPGOING" fullword ascii
      $s3 = "upgrade_implant" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 200KB and 2 of them ) or ( all of them )
}