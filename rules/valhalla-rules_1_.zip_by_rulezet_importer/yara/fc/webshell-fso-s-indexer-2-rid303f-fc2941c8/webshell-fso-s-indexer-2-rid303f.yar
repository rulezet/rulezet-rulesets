rule Webshell_FSO_s_indexer_2_RID303F : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file indexer.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:31:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s5 = "<td>Nerden :<td><input type=\"text\" name=\"nerden\" size=25 value=index.html></td>" 
   condition: 
      all of them
}