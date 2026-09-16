rule APT_EQGRP_epicbanana_2_1_0_1_RID3075 : APT DEMO SCRIPT {
   meta:
      description = "EQGRP Toolset Firewall - file epicbanana_2.1.0.1.py"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 12:40:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4b13cc183c3aaa8af43ef3721e254b54296c8089a0cd545ee3b867419bb66f61"
      tags = "APT, DEMO, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "failed to create version-specific payload" fullword ascii
      $s2 = "(are you sure you did \"make [version]\" in versions?)" fullword ascii
   condition: 
      1 of them
}