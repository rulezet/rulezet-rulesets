rule Webshell_c99madshell_v2_RID2FCC : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:12:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3ca5886cd54d495dc95793579611f59a"
      hash2 = "9c5bb5e3a46ec28039e8986324e42792"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<b>Dumped! Dump has been writed to " 
      $s1 = "if ((!empty($donated_html)) and (in_array($act,$donated_act))) {echo \"<TABLE st" 
      $s2 = "<input type=submit name=actarcbuff value=\\\"Pack buffer to archive" 
   condition: 
      1 of them
}