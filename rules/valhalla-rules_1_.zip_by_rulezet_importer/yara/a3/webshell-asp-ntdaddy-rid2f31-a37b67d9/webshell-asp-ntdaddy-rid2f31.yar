rule Webshell_asp_ntdaddy_RID2F31 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file ntdaddy.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:46:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s9 = "if  FP  =  \"RefreshFolder\"  or  " 
      $s10 = "request.form(\"cmdOption\")=\"DeleteFolder\"  " 
   condition: 
      1 of them
}