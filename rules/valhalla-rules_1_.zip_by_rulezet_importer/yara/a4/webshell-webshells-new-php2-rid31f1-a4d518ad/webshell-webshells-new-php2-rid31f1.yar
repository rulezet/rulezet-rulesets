rule Webshell_webshells_new_php2_RID31F1 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file php2.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:44:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<?php $s=@$_GET[2];if(md5($s.$s)==" 
   condition: 
      all of them
}