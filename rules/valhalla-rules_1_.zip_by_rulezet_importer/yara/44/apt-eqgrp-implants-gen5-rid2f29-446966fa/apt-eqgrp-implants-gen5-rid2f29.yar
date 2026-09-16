rule APT_EQGRP_Implants_Gen5_RID2F29 : APT DEMO FILE {
   meta:
      description = "EQGRP Toolset Firewall - from files BananaUsurper-2120, BARPUNCH-3110, BLIAR-2110, BLIQUER-2230, BLIQUER-3030, BLIQUER-3120, BPICKER-3100, writeJetPlow-2130"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 11:45:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3366b4bbf265716869a487203a8ac39867920880990493dd4dd8385e42b0c119"
      hash2 = "830538fe8c981ca386c6c7d55635ac61161b23e6e25d96280ac2fc638c2d82cc"
      hash3 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
      tags = "APT, DEMO, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Module and Implant versions do not match.  This module is not compatible with the target implant" fullword ascii
      $s1 = "%s/BF_READ_%08x_%04d%02d%02d_%02d%02d%02d.log" fullword ascii
      $s2 = "%s/BF_%04d%02d%02d.log" fullword ascii
      $s3 = "%s/BF_READ_%08x_%04d%02d%02d_%02d%02d%02d.bin" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and 1 of ( $x* ) ) or ( all of them )
}