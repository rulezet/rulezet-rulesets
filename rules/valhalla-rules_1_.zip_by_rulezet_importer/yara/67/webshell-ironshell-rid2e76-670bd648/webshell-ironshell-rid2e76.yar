rule Webshell_ironshell_RID2E76 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file ironshell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:15:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "print \"<form action=\\\"\".$me.\"?p=cmd&dir=\".realpath('.').\"" 
      $s8 = "print \"<td id=f><a href=\\\"?p=rename&file=\".realpath($file).\"&di" 
   condition: 
      all of them
}