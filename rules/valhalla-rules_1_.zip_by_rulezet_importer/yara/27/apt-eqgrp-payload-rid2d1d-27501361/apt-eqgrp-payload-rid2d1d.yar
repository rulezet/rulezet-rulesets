rule APT_EQGRP_payload_RID2D1D : APT DEMO SCRIPT {
   meta:
      description = "EQGRP Toolset Firewall - file payload.py"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 10:18:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "21bed6d699b1fbde74cbcec93575c9694d5bea832cd191f59eb3e4140e5c5e07"
      tags = "APT, DEMO, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "can't find target version module!" fullword ascii
      $s2 = "class Payload:" fullword ascii
   condition: 
      all of them
}