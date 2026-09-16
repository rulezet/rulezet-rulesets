rule APT_EQGRP_tunnel_state_reader_RID321B : APT DEMO {
   meta:
      description = "EQGRP Toolset Firewall - file tunnel_state_reader"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 13:51:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "49d48ca1ec741f462fde80da68b64dfa5090855647520d29e345ef563113616c"
      tags = "APT, DEMO"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Active connections will be maintained for this tunnel. Timeout:" fullword ascii
      $s5 = "%s: compatible with BLATSTING version 1.2" fullword ascii
   condition: 
      1 of them
}