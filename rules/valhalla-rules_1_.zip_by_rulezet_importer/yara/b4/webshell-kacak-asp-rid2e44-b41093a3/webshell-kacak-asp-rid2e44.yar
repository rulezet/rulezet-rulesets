rule Webshell_kacak_asp_RID2E44 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file kacak.asp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:07:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Kacak FSO 1.0" 
      $s1 = "if request.querystring(\"TGH\") = \"1\" then" 
      $s3 = "<font color=\"#858585\">BuqX</font></a></font><font face=\"Verdana\" style=" 
      $s4 = "mailto:BuqX@hotmail.com" 
   condition: 
      1 of them
}