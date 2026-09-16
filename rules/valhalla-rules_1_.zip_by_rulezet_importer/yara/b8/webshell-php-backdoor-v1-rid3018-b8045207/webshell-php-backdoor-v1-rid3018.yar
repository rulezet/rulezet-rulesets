rule Webshell_PHP_Backdoor_v1_RID3018 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file PHP Backdoor v1.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 12:25:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s5 = "echo\"<form method=\\\"POST\\\" action=\\\"\".$_SERVER['PHP_SELF'].\"?edit=\".$th" 
      $s8 = "echo \"<a href=\\\"\".$_SERVER['PHP_SELF'].\"?proxy" 
   condition: 
      all of them
}