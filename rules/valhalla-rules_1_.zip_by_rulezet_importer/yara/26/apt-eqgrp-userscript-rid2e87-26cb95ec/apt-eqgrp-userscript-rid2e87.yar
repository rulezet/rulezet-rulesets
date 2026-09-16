rule APT_EQGRP_userscript_RID2E87 : APT DEMO {
   meta:
      description = "EQGRP Toolset Firewall - file userscript.FW"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 11:18:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "5098ff110d1af56115e2c32f332ff6e3973fb7ceccbd317637c9a72a3baa43d7"
      tags = "APT, DEMO"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Are you sure? Don't forget that NETSCREEN firewalls require BANANALIAR!! " fullword ascii
   condition: 
      1 of them
}