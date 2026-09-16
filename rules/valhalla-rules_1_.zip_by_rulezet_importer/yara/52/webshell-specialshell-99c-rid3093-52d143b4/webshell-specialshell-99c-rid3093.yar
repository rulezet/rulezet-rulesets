rule Webshell_SpecialShell_99c_RID3093 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, SsEs.php.php.txt, SpecialShell_99.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:45:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3ca5886cd54d495dc95793579611f59a"
      hash2 = "9c5bb5e3a46ec28039e8986324e42792"
      hash3 = "6cd50a14ea0da0df6a246a60c8f6f9c9"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "else {$act = \"f\"; $d = dirname($mkfile); if (substr($d,-1) != DIRECTORY_SEPA" 
      $s3 = "else {echo \"<b>File \\\"\".$sql_getfile.\"\\\":</b><br>\".nl2br(htmlspec" 
   condition: 
      1 of them
}