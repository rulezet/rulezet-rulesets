rule APT_EQGRP_Implants_Gen3_RID2F27 : APT DEMO FILE {
   meta:
      description = "EQGRP Toolset Firewall - from files BARPUNCH-3110, BLIAR-2110, BLIQUER-2230, BLIQUER-3030, BLIQUER-3120, BPICKER-3100"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 11:45:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "830538fe8c981ca386c6c7d55635ac61161b23e6e25d96280ac2fc638c2d82cc"
      hash2 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
      hash3 = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
      tags = "APT, DEMO, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "incomplete and must be removed manually.)" fullword ascii
      $s1 = "%s: recv'd an error from the target." fullword ascii
      $s2 = "Unable to fetch the address to the get_uptime_secs function for this OS version" fullword ascii
      $s3 = "upload/activate/de-activate/remove/cmd function failed" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 6000KB and 2 of them ) or ( all of them )
}