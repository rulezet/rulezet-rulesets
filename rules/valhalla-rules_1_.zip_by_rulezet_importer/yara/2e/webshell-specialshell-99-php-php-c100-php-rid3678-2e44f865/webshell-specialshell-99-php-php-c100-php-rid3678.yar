rule Webshell_SpecialShell_99_php_php_c100_php_RID3678 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files wacking.php.php.txt, 1.txt, SpecialShell_99.php.php.txt, c100.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 16:57:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "44542e5c3e9790815c49d5f9beffbbf2"
      hash2 = "09609851caa129e40b0d56e90dfc476c"
      hash3 = "38fd7e45f9c11a37463c3ded1c76af4c"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "if(eregi(\"./shbd $por\",$scan))" 
      $s1 = "$_POST['backconnectip']" 
      $s2 = "$_POST['backcconnmsg']" 
   condition: 
      1 of them
}