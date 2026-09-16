rule APT_EQGRP_BPIE_RID2B53 : APT DEMO FILE {
   meta:
      description = "EQGRP Toolset Firewall - file BPIE-2201.exe"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 09:01:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "697e80cf2595c85f7c931693946d295994c55da17a400f2c9674014f130b4688"
      tags = "APT, DEMO, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "profProcessPacket" fullword ascii
      $s2 = ".got_loader" fullword ascii
      $s3 = "getTimeSlotCmdHandler" fullword ascii
      $s4 = "getIpIpCmdHandler" fullword ascii
      $s5 = "LOADED" fullword ascii
      $s6 = "profStartScan" fullword ascii
      $s7 = "tmpData.1" fullword ascii
      $s8 = "resetCmdHandler" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 70KB and 6 of ( $s* ) )
}