rule Webshell_phpshell17_php_RID3015 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file phpshell17.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:24:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<input name=\"submit_btn\" type=\"submit\" value=\"Execute Command\"></p>" fullword
      $s1 = "<title>[ADDITINAL TITTLE]-phpShell by:[YOURNAME]<?php echo PHPSHELL_VERSION ?></" 
      $s2 = "href=\"mailto: [YOU CAN ENTER YOUR MAIL HERE]- [ADDITIONAL TEXT]</a></i>" fullword
   condition: 
      1 of them
}