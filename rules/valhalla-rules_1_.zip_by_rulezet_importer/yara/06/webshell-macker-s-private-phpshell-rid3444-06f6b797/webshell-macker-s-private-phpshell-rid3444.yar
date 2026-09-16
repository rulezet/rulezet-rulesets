rule Webshell_Macker_s_Private_PHPShell_RID3444 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Macker's Private PHPShell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 15:23:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "echo \"<tr><td class=\\\"silver border\\\">&nbsp;<strong>Server's PHP Version:&n" 
      $s4 = "&nbsp;&nbsp;<?php echo buildUrl(\"<font color=\\\"navy\\\">[" 
      $s7 = "echo \"<form action=\\\"$SFileName?$urlAdd\\\" method=\\\"POST\\\"><input type=" 
   condition: 
      all of them
}