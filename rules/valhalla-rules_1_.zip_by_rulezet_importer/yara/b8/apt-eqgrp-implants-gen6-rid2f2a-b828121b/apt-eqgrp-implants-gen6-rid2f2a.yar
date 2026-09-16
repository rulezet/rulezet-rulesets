rule APT_EQGRP_Implants_Gen6_RID2F2A : APT DEMO FILE {
   meta:
      description = "EQGRP Toolset Firewall - from files BananaUsurper-2120, BLIAR-2110, BLIQUER-2230, BLIQUER-3030, BLIQUER-3120, BPICKER-3100, writeJetPlow-2130"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 11:45:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3366b4bbf265716869a487203a8ac39867920880990493dd4dd8385e42b0c119"
      hash2 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
      hash3 = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
      tags = "APT, DEMO, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "LP.c:pixSecurity - Improper number of bytes read in Security/Interface Information" fullword ascii
      $s2 = "LP.c:pixSecurity - Not in Session" fullword ascii
      $s3 = "getModInterface__preloadedModules" fullword ascii
      $s4 = "showCommands" fullword ascii
      $s5 = "readModuleInterface" fullword ascii
      $s6 = "Wrapping_Not_Necessary_Or_Wrapping_Ok" fullword ascii
      $s7 = "Get_CMD_List" fullword ascii
      $s8 = "LP_Listen2" fullword ascii
      $s9 = "killCmdList" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 6000KB and all of them )
}