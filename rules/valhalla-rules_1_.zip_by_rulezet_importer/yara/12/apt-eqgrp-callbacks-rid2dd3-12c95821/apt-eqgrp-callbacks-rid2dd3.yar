rule APT_EQGRP_callbacks_RID2DD3 : APT DEMO {
   meta:
      description = "EQGRP Toolset Firewall - Callback addresses"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 10:48:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "30.40.50.60:9342" fullword ascii wide
   condition: 
      1 of them
}