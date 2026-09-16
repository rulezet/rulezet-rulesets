rule Webshell_indexer_asp_RID2F38 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file indexer.asp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:47:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<td>Nereye :<td><input type=\"text\" name=\"nereye\" size=25></td><td><input typ" 
      $s2 = "D7nD7l.km4snk`JzKnd{n_ejq;bd{KbPur#kQ8AAA==^#~@%>></td><td><input type=\"submit" 
   condition: 
      1 of them
}