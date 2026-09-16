rule Webshell_PHP_bug_1__RID2E1A : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file bug (1).php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:00:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "@include($_GET['bug']);" fullword
   condition: 
      all of them
}