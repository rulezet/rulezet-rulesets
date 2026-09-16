rule Webshell_xssshell_db_RID2F41 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file db.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:49:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s8 = "'// By Ferruh Mavituna | http://ferruh.mavituna.com" 
   condition: 
      all of them
}