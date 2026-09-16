rule Webshell_Inderxer_RID2DE7 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Inderxer.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:51:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "<td>Nereye :<td><input type=\"text\" name=\"nereye\" size=25></td><td><input typ" 
   condition: 
      all of them
}