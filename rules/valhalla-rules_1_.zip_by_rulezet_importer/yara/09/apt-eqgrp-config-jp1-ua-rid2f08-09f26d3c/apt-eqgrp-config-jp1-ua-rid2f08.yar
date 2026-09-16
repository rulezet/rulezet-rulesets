rule APT_EQGRP_config_jp1_UA_RID2F08 : APT DEMO {
   meta:
      description = "EQGRP Toolset Firewall - file config_jp1_UA.pl"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 11:39:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2f50b6e9891e4d7fd24cc467e7f5cfe348f56f6248929fec4bbee42a5001ae56"
      tags = "APT, DEMO"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "This program will configure a JETPLOW Userarea file." fullword ascii
      $x2 = "Error running config_implant." fullword ascii
      $x3 = "NOTE:  IT ASSUMES YOU ARE OPERATING IN THE INSTALL/LP/JP DIRECTORY. THIS ASSUMPTION " fullword ascii
      $x4 = "First IP address for beacon destination [127.0.0.1]" fullword ascii
   condition: 
      1 of them
}