rule Webshell_webshells_new_xxxx_RID3257 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file xxxx.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 14:01:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<?php eval($_POST[1]);?>  " fullword
   condition: 
      all of them
}