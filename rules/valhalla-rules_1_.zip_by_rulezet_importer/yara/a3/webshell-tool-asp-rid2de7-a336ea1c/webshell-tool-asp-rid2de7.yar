rule Webshell_Tool_asp_RID2DE7 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Tool.asp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 10:51:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "mailto:rhfactor@antisocial.com" 
      $s2 = "?raiz=root" 
      $s3 = "DIGO CORROMPIDO<BR>CORRUPT CODE" 
      $s4 = "key = \"5DCADAC1902E59F7273E1902E5AD8414B1902E5ABF3E661902E5B554FC41902E53205CA0" 
   condition: 
      2 of them
}