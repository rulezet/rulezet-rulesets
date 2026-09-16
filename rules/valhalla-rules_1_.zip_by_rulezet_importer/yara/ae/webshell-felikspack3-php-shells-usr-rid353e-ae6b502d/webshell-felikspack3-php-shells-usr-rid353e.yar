rule Webshell_FeliksPack3___PHP_Shells_usr_RID353E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file usr.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 16:04:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<?php $id_info = array('notify' => 'off','sub' => 'aasd','s_name' => 'nurullahor" 
   condition: 
      all of them
}