rule Webshell_jsp_guige_RID2E63 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file guige.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:12:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "if(damapath!=null &&!damapath.equals(\"\")&&content!=null" 
   condition: 
      all of them
}