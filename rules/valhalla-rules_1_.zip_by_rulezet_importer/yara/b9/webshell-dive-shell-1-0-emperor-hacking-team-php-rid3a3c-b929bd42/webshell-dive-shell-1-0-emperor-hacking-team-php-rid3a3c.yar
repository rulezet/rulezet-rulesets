rule Webshell_Dive_Shell_1_0___Emperor_Hacking_Team_php_RID3A3C : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Dive Shell 1.0 - Emperor Hacking Team.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 19:37:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Emperor Hacking TEAM" 
      $s1 = "Simshell" fullword
      $s2 = "ereg('^[[:blank:]]*cd[[:blank:]]" 
      $s3 = "<form name=\"shell\" action=\"<?php echo $_SERVER['PHP_SELF'] ?>\" method=\"POST" 
   condition: 
      2 of them
}