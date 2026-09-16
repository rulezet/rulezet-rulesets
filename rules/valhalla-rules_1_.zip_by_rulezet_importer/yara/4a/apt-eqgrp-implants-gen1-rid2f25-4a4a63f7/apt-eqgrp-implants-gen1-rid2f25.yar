rule APT_EQGRP_Implants_Gen1_RID2F25 : APT DEMO FILE {
   meta:
      description = "EQGRP Toolset Firewall - from files BananaUsurper-2120, BARPUNCH-3110, BLIAR-2110, BLIQUER-2230, BLIQUER-3030, BLIQUER-3120, BPICKER-3100, lpexe, writeJetPlow-2130"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 11:44:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3366b4bbf265716869a487203a8ac39867920880990493dd4dd8385e42b0c119"
      hash2 = "830538fe8c981ca386c6c7d55635ac61161b23e6e25d96280ac2fc638c2d82cc"
      hash3 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
      tags = "APT, DEMO, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "WARNING:  Session may not have been closed!" fullword ascii
      $s2 = "EXEC Packet Processed" fullword ascii
      $s3 = "Failed to insert the command into command list." fullword ascii
      $s4 = "Send_Packet: Trying to send too much data." fullword ascii
      $s5 = "payloadLength >= MAX_ALLOW_SIZE." fullword ascii
      $s6 = "Wrong Payload Size" fullword ascii
      $s7 = "Unknown packet received......" fullword ascii
      $s8 = "Returned eax = %08x" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 6000KB and ( 2 of ( $s* ) ) ) or ( 5 of them )
}