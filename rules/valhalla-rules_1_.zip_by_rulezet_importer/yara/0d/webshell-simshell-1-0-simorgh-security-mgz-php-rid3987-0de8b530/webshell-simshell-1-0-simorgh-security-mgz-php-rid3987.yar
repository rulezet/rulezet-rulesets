rule Webshell_SimShell_1_0___Simorgh_Security_MGZ_php_RID3987 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file SimShell 1.0 - Simorgh Security MGZ.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 19:07:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Simorgh Security Magazine " 
      $s1 = "Simshell.css" 
      $s2 = "} elseif (ereg('^[[:blank:]]*cd[[:blank:]]+([^;]+)$', $_REQUEST['command'], " 
      $s3 = "www.simorgh-ev.com" 
   condition: 
      2 of them
}