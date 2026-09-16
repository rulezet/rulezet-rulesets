rule Webshell_PHP_b37_RID2CB9 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file b37.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:01:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "xmg2/G4MZ7KpNveRaLgOJvBcqa2A8/sKWp9W93NLXpTTUgRc" 
   condition: 
      all of them
}