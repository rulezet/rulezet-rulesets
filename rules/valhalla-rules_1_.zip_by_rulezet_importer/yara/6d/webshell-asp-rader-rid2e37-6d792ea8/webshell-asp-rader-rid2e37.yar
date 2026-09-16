rule Webshell_asp_Rader_RID2E37 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Rader.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:05:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "FONT-WEIGHT: bold; FONT-SIZE: 10px; BACKGROUND: none transparent scroll repeat 0" 
      $s3 = "m\" target=inf onClick=\"window.open('?action=help','inf','width=450,height=400 " 
   condition: 
      all of them
}