rule APT_EQGRP_BUSURPER_2211_724_RID2ECC : APT DEMO {
   meta:
      description = "EQGRP Toolset Firewall - file BUSURPER-2211-724.exe"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 11:29:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d809d6ff23a9eee53d2132d2c13a9ac5d0cb3037c60e229373fc59a4f14bc744"
      tags = "APT, DEMO"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = ".got_loader" fullword ascii
      $s2 = "_start_text" ascii
      $s3 = "IMPLANT" fullword ascii
      $s4 = "KEEPGOING" fullword ascii
      $s5 = "upgrade_implant" fullword ascii
   condition: 
      all of them
}