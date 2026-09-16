rule APT_EQGRP_uninstallPBD_RID2EE3 : APT DEMO SCRIPT {
   meta:
      description = "EQGRP Toolset Firewall - file uninstallPBD.bat"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 11:33:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "692fdb449f10057a114cf2963000f52ce118d9a40682194838006c66af159bd0"
      tags = "APT, DEMO, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "memset 00e9a05c 4 38845b88" fullword ascii
      $s2 = "_hidecmd" ascii
      $s3 = "memset 013abd04 1 0d" fullword ascii
   condition: 
      all of them
}