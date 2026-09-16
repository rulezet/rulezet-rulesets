rule APT_EQGRP_BBALL_M50FW08_2201_RID2ECA : APT DEMO FILE {
   meta:
      description = "EQGRP Toolset Firewall - file BBALL_M50FW08-2201.exe"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 11:29:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "80c0b68adb12bf3c15eff9db70a57ab999aad015da99c4417fdfd28156d8d3f7"
      tags = "APT, DEMO, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = ".got_loader" fullword ascii
      $s2 = "LOADED" fullword ascii
      $s3 = "pageTable.c" fullword ascii
      $s4 = "_start_text" ascii
      $s5 = "handler_readBIOS" fullword ascii
      $s6 = "KEEPGOING" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 40KB and 5 of ( $s* ) )
}