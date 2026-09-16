rule Webshell_asp_1_RID2C7A : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file 1.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 09:50:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "!22222222222222222222222222222222222222222222222222" fullword
      $s8 = "<%eval request(\"pass\")%>" fullword
   condition: 
      all of them
}