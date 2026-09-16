rule APT_EQGRP_BananaAid_RID2D82 : APT DEMO T1105 {
   meta:
      description = "EQGRP Toolset Firewall - file BananaAid"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 10:34:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7a4fb825e63dc612de81bc83313acf5eccaa7285afc05941ac1fef199279519f"
      tags = "APT, DEMO, T1105"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "(might have to delete key in ~/.ssh/known_hosts on linux box)" fullword ascii
      $x2 = "scp BGLEE-" ascii
      $x3 = "should be 4bfe94b1 for clean bootloader version 3.0; " fullword ascii
      $x4 = "scp <configured implant> <username>@<IPaddr>:onfig" fullword ascii
   condition: 
      1 of them
}