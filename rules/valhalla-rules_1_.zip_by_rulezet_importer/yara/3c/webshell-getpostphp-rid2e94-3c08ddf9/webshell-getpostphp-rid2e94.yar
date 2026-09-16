rule Webshell_GetPostpHp_RID2E94 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file GetPostpHp.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 11:20:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<?php eval(str_rot13('riny($_CBFG[cntr]);'));?>" fullword
   condition: 
      all of them
}