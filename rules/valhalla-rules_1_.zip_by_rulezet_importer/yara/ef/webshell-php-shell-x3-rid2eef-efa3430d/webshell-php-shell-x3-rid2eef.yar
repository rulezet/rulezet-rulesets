rule Webshell_PHP_Shell_x3_RID2EEF : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file PHP Shell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:35:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "&nbsp;&nbsp;<?php echo buildUrl(\"<font color=\\\"navy\\\">[" 
      $s6 = "echo \"</form><form action=\\\"$SFileName?$urlAdd\\\" method=\\\"post\\\"><input" 
      $s9 = "if  ( ( (isset($http_auth_user) ) && (isset($http_auth_pass)) ) && ( !isset(" 
   condition: 
      2 of them
}