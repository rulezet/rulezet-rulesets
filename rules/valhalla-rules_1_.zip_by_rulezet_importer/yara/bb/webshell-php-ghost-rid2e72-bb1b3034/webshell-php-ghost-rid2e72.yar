rule Webshell_php_ghost_RID2E72 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file ghost.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:14:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<?php $OOO000000=urldecode('%61%68%36%73%62%65%68%71%6c%61%34%63%6f%5f%73%61%64'" 
      $s6 = "//<img width=1 height=1 src=\"http://websafe.facaiok.com/just7z/sx.asp?u=***.***" 
      $s7 = "preg_replace('\\'a\\'eis','e'.'v'.'a'.'l'.'(KmU(\"" fullword
   condition: 
      all of them
}