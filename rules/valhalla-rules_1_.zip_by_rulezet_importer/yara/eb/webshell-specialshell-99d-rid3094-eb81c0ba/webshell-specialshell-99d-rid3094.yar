rule Webshell_SpecialShell_99d_RID3094 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files w.php.php.txt, wacking.php.php.txt, c99shell_v1.0.php.php.txt, c99php.txt, SpecialShell_99.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:45:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9c5bb5e3a46ec28039e8986324e42792"
      hash2 = "d8ae5819a0a2349ec552cbcf3a62c975"
      hash3 = "9e9ae0332ada9c3797d6cee92c2ede62"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$sqlquicklaunch[] = array(\"" 
      $s1 = "else {echo \"<center><b>File does not exists (\".htmlspecialchars($d.$f).\")!<" 
   condition: 
      all of them
}