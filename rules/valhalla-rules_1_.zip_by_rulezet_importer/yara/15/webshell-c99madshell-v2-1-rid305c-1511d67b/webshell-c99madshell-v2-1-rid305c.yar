rule Webshell_c99madshell_v2_1_RID305C : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, c99shell_v1.0.php.php.txt, c99php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:36:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3ca5886cd54d495dc95793579611f59a"
      hash2 = "9c5bb5e3a46ec28039e8986324e42792"
      hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "@ini_set(\"highlight" fullword
      $s1 = "echo \"<b>Result of execution this PHP-code</b>:<br>\";" fullword
      $s2 = "{$row[] = \"<b>Owner/Group</b>\";}" fullword
   condition: 
      2 of them
}