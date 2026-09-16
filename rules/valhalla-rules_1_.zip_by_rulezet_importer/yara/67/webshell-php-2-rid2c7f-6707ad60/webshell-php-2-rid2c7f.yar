rule Webshell_php_2_RID2C7F : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file 2.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 09:51:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<?php assert($_REQUEST[\"c\"]);?> " fullword
   condition: 
      all of them
}