rule Webshell_SpecialShell_99_php_php_a_RID343E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, 1.txt, SpecialShell_99.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 15:22:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3ca5886cd54d495dc95793579611f59a"
      hash2 = "9c5bb5e3a46ec28039e8986324e42792"
      hash3 = "44542e5c3e9790815c49d5f9beffbbf2"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "if ($total === FALSE) {$total = 0;}" fullword
      $s1 = "$free_percent = round(100/($total/$free),2);" fullword
      $s2 = "if (!$bool) {$bool = is_dir($letter.\":\\\\\");}" fullword
      $s3 = "$bool = $isdiskette = in_array($letter,$safemode_diskettes);" fullword
   condition: 
      2 of them
}