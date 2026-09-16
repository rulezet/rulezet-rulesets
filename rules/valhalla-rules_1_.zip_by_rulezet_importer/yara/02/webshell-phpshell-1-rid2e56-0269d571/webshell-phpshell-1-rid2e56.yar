rule Webshell_PhpShell_1_RID2E56 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file PhpShell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:10:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "href=\"http://www.gimpster.com/wiki/PhpShell\">www.gimpster.com/wiki/PhpShell</a>." 
   condition: 
      all of them
}