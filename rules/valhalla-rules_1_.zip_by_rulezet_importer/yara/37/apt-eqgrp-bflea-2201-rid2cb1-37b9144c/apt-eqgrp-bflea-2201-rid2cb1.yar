rule APT_EQGRP_BFLEA_2201_RID2CB1 : APT DEMO FILE {
   meta:
      description = "EQGRP Toolset Firewall - file BFLEA-2201.exe"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 10:00:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "15e8c743770e44314496c5f27b6297c5d7a4af09404c4aa507757e0cc8edc79e"
      tags = "APT, DEMO, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = ".got_loader" fullword ascii
      $s2 = "LOADED" fullword ascii
      $s3 = "readFlashHandler" fullword ascii
      $s4 = "KEEPGOING" fullword ascii
      $s5 = "flashRtnsPix6x.c" fullword ascii
      $s6 = "fix_ip_cksum_incr" fullword ascii
      $s7 = "writeFlashHandler" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 30KB and 5 of them ) or ( all of them )
}