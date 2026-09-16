rule APT_EQGRP_durablenapkin_solaris_2_0_1_RID349F : APT DEMO FILE {
   meta:
      description = "Detects tool from EQGRP toolset - file durablenapkin.solaris.2.0.1.1"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-15 15:38:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "recv_ack: %s: Service not supplied by provider" fullword ascii
      $s2 = "send_request: putmsg \"%s\": %s" fullword ascii
      $s3 = "port undefined" fullword ascii
      $s4 = "recv_ack: %s getmsg: %s" fullword ascii
      $s5 = ">> %d -- %d" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 40KB and 2 of them )
}