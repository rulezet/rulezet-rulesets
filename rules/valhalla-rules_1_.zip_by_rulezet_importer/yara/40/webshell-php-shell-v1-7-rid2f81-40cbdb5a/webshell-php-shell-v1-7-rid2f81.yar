rule Webshell_PHP_Shell_v1_7_RID2F81 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file PHP_Shell_v1.7.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:00:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s8 = "<title>[ADDITINAL TITTLE]-phpShell by:[YOURNAME]" 
   condition: 
      all of them
}