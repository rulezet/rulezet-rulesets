rule APT_EQGRP_BICECREAM_RID2CAE : APT DEMO FILE {
   meta:
      description = "EQGRP Toolset Firewall - file BICECREAM-2140"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 09:59:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4842076af9ba49e6dfae21cf39847b4172c06a0bd3d2f1ca6f30622e14b77210"
      tags = "APT, DEMO, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Could not connect to target device: %s:%d. Please check IP address." fullword ascii
      $s2 = "command data size is invalid for an exec cmd" fullword ascii
      $s3 = "A script was specified but target is not a PPC405-based NetScreen (NS5XT, NS25, and NS50). Executing scripts is supported but ma" ascii
      $s4 = "Execute 0x%08x with args (%08x, %08x, %08x, %08x): [y/n]" fullword ascii
      $s5 = "Execute 0x%08x with args (%08x, %08x, %08x): [y/n]" fullword ascii
      $s6 = "[%d] Execute code." fullword ascii
      $s7 = "Execute 0x%08x with args (%08x): [y/n]" fullword ascii
      $s8 = "dump_value_LHASH_DOALL_ARG" fullword ascii
      $s9 = "Eggcode is complete. Pass execution to it? [y/n]" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 5000KB and 2 of them ) or ( 5 of them )
}