rule Webshell_asp_01_RID2CAA : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file 01.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 09:58:51"
      score = 50
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<%eval request(\"pass\")%>" fullword
   condition: 
      all of them
}