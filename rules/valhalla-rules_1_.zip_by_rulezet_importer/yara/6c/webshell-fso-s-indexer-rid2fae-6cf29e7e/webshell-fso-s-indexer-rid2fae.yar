rule Webshell_FSO_s_indexer_RID2FAE : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file indexer.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:07:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "<td>Nereye :<td><input type=\"text\" name=\"nereye\" size=25></td><td><input type=\"r" 
   condition: 
      all of them
}