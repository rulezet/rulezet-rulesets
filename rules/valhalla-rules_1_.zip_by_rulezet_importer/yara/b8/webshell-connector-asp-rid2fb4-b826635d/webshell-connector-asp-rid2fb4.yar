rule Webshell_connector_ASP_RID2FB4 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file connector.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:08:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "If ( AttackID = BROADCAST_ATTACK )" 
      $s4 = "Add UNIQUE ID for victims / zombies" 
   condition: 
      all of them
}