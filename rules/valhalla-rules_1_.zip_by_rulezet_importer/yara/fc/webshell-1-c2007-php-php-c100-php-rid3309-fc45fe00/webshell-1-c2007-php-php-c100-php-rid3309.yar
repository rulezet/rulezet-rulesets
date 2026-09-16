rule Webshell__1_c2007_php_php_c100_php_RID3309 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files 1.txt, c2007.php.php.txt, c100.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 14:30:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d089e7168373a0634e1ac18c0ee00085"
      hash2 = "38fd7e45f9c11a37463c3ded1c76af4c"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "echo \"<b>Changing file-mode (\".$d.$f.\"), \".view_perms_color($d.$f).\" (\"" 
      $s3 = "echo \"<td>&nbsp;<a href=\\\"\".$sql_surl.\"sql_act=query&sql_query=\".ur" 
   condition: 
      1 of them
}