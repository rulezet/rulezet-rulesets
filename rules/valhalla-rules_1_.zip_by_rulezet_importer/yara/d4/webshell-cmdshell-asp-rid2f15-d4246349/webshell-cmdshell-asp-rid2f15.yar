rule Webshell_cmdShell_ASP_RID2F15 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file cmdShell.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:42:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "if cmdPath=\"wscriptShell\" then" 
   condition: 
      all of them
}