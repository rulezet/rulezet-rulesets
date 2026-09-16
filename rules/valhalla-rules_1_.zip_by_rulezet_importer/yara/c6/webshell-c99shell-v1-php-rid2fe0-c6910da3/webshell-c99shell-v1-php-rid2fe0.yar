rule Webshell_c99shell_v1_PHP_RID2FE0 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files c99shell_v1.0.php.php.txt, c99php.txt, 1.txt, c2007.php.php.txt, c100.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:15:51"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9e9ae0332ada9c3797d6cee92c2ede62"
      hash2 = "44542e5c3e9790815c49d5f9beffbbf2"
      hash3 = "d089e7168373a0634e1ac18c0ee00085"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$result = mysql_query(\"SHOW PROCESSLIST\", $sql_sock); " fullword
   condition: 
      all of them
}