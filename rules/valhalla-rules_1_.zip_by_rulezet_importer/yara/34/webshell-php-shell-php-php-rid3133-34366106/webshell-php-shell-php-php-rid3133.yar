rule Webshell_PHP_Shell_php_php_RID3133 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file PHP Shell.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:12:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "echo \"</form><form action=\\\"$SFileName?$urlAdd\\\" method=\\\"post\\\"><input" 
      $s1 = "echo \"<form action=\\\"$SFileName?$urlAdd\\\" method=\\\"POST\\\"><input type=" 
   condition: 
      all of them
}