rule Webshell_PHP_sh_RID2CC8 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file sh.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 10:03:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\"@$SERVER_NAME \".exec(\"pwd\")" 
   condition: 
      all of them
}