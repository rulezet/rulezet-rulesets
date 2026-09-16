rule Webshell_SpecialShell_99_php_c_RID3299 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files w.php.php.txt, wacking.php.php.txt, SsEs.php.php.txt, SpecialShell_99.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 14:12:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9c5bb5e3a46ec28039e8986324e42792"
      hash2 = "6cd50a14ea0da0df6a246a60c8f6f9c9"
      hash3 = "09609851caa129e40b0d56e90dfc476c"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "\"ext_avi\"=>array(\"ext_avi\",\"ext_mov\",\"ext_mvi" 
      $s1 = "echo \"<b>Execute file:</b><form action=\\\"\".$surl.\"\\\" method=POST><inpu" 
      $s2 = "\"ext_htaccess\"=>array(\"ext_htaccess\",\"ext_htpasswd" 
   condition: 
      1 of them
}