rule Webshell_pHpINJ_php_php_RID2FFD : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file pHpINJ.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:20:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "News Remote PHP Shell Injection" 
      $s3 = "Php Shell <br />" fullword
      $s4 = "<input type = \"text\" name = \"url\" value = \"" 
   condition: 
      2 of them
}