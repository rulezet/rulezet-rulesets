rule Webshell_webshells_new_PHP_RID315F : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file PHP.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:19:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "echo \"<font color=blue>Error!</font>\";" fullword
      $s2 = "<input type=\"text\" size=61 name=\"f\" value='<?php echo $_SERVER[\"SCRIPT_FILE" 
      $s5 = " - ExpDoor.com</title>" fullword
      $s10 = "$f=fopen($_POST[\"f\"],\"w\");" fullword
      $s12 = "<textarea name=\"c\" cols=60 rows=15></textarea><br>" fullword
   condition: 
      1 of them
}