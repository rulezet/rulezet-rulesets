rule Webshell_jsp_up_RID2D37 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file up.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:22:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s9 = "// BUG: Corta el fichero si es mayor de 640Ks" fullword
   condition: 
      all of them
}