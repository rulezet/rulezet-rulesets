rule Webshell_asp_shell_RID2E61 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file shell.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:12:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s7 = "<input type=\"submit\" name=\"Send\" value=\"GO!\">" fullword
      $s8 = "<TEXTAREA NAME=\"1988\" ROWS=\"18\" COLS=\"78\"></TEXTAREA>" fullword
   condition: 
      all of them
}