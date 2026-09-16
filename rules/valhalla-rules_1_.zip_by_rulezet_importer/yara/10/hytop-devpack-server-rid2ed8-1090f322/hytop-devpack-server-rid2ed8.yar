rule HYTop_DevPack_server_RID2ED8 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file server.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:31:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<!-- PageServer Below -->" 
   condition: 
      all of them
}