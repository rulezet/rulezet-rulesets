rule Webshell_Webshell_php_Blocker_RID32A4 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file webshell.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 14:13:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "<die(\"Couldn't Read directory, Blocked!!!\");" 
      $s3 = "PHP Web Shell" 
   condition: 
      all of them
}