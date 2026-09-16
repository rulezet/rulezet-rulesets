rule APT_EQGRP_screamingplow_RID2FAE : APT DEMO SCRIPT {
   meta:
      description = "EQGRP Toolset Firewall - file screamingplow.sh"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 12:07:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c7f4104c4607a03a1d27c832e1ebfc6ab252a27a1709015b5f1617b534f0090a"
      tags = "APT, DEMO, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "What is the name of your PBD:" fullword ascii
      $s2 = "You are now ready for a ScreamPlow" fullword ascii
   condition: 
      1 of them
}