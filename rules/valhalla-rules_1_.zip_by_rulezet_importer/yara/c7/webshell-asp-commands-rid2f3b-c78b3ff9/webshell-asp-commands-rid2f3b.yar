rule Webshell_ASP_commands_RID2F3B : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file commands.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:48:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "If CheckRecord(\"SELECT COUNT(ID) FROM VictimDetail WHERE VictimID = \" & VictimID" 
      $s2 = "proxyArr = Array (\"HTTP_X_FORWARDED_FOR\",\"HTTP_VIA\",\"HTTP_CACHE_CONTROL\",\"HTTP_F" 
   condition: 
      all of them
}