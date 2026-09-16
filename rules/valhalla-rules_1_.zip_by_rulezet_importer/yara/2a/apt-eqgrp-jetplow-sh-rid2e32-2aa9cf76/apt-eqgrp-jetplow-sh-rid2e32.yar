rule APT_EQGRP_jetplow_SH_RID2E32 : APT DEMO SCRIPT {
   meta:
      description = "EQGRP Toolset Firewall - file jetplow.sh"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 11:04:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ee266f84a1a4ccf2e789a73b0a11242223ed6eba6868875b5922aea931a2199c"
      tags = "APT, DEMO, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "cd /current/bin/FW/BANANAGLEE/$bgver/Install/LP/jetplow" fullword ascii
      $s2 = "***** Please place your UA in /current/bin/FW/OPS *****" fullword ascii
      $s3 = "ln -s ../jp/orig_code.bin orig_code_pixGen.bin" fullword ascii
      $s4 = "*****             Welcome to JetPlow              *****" fullword ascii
   condition: 
      1 of them
}