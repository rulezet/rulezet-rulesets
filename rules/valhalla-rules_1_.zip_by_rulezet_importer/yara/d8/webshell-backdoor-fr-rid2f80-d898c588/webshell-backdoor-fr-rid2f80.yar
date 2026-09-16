rule Webshell_BackDooR__fr__RID2F80 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file BackDooR (fr).php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:59:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "print(\"<p align=\\\"center\\\"><font size=\\\"5\\\">Exploit include " 
   condition: 
      all of them
}