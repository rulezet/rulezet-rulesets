rule Webshell_redirect_RID2DF8 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file redirect.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:54:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s7 = "var flag = \"?txt=\" + (document.getElementById(\"dl\").checked ? \"2\":\"1\" " 
   condition: 
      all of them
}