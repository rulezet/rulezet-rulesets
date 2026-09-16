rule APT_EQGRP_Unique_Strings_RID2FF3 : APT DEMO {
   meta:
      description = "EQGRP Toolset Firewall - Unique strings"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 12:19:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "/BananaGlee/ELIGIBLEBOMB" ascii
      $s2 = "Protocol must be either http or https (Ex: https://1.2.3.4:1234)" 
   condition: 
      1 of them
}