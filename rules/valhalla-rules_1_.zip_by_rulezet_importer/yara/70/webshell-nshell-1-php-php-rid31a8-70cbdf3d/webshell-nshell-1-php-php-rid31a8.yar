rule Webshell_Nshell__1__php_php_RID31A8 : DEMO T1033 T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Nshell (1).php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:31:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1033, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "echo \"Command : <INPUT TYPE=text NAME=cmd value=\".@stripslashes(htmlentities($" 
      $s1 = "if(!$whoami)$whoami=exec(\"whoami\"); echo \"whoami :\".$whoami.\"<br>\";" fullword
   condition: 
      1 of them
}