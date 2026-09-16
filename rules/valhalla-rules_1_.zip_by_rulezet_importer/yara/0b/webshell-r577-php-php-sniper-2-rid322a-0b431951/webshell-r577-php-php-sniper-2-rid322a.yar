rule Webshell_r577_php_php_SnIpEr_2_RID322A : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files r577.php.php.txt, SnIpEr_SA Shell.php.txt, r57.php.php.txt, r57 Shell.php.php.txt, spy.php.php.txt, s.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:53:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "911195a9b7c010f61b66439d9048f400"
      hash2 = "eddf7a8fde1e50a7f2a817ef7cece24f"
      hash3 = "8023394542cddf8aee5dec6072ed02b5"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "'eng_text71'=>\"Second commands param is:\\r\\n- for CHOWN - name of new owner o" 
      $s4 = "if(!empty($_POST['s_mask']) && !empty($_POST['m'])) { $sr = new SearchResult" 
   condition: 
      1 of them
}