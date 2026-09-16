rule APT_EQGRP_BBANJO_RID2BDF : APT DEMO FILE {
   meta:
      description = "EQGRP Toolset Firewall - file BBANJO-3011.exe"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 09:25:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "f09c2f90464781a08436321f6549d350ecef3d92b4f25b95518760f5d4c9b2c3"
      tags = "APT, DEMO, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "get_lsl_interfaces" fullword ascii
      $s2 = "encryptFC4Payload" fullword ascii
      $s3 = ".got_loader" fullword ascii
      $s4 = "beacon_getconfig" fullword ascii
      $s5 = "LOADED" fullword ascii
      $s6 = "FormBeaconPacket" fullword ascii
      $s7 = "beacon_reconfigure" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 50KB and all of them )
}