rule Webshell_nst_perl_proxy_shell_RID3325 : DEMO SCRIPT T1090 T1105 T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files nst.php.php.txt, img.php.php.txt, nstview.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 14:35:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "17a07bb84e137b8aa60f87cd6bfab748"
      hash2 = "4745d510fed4378e4b1730f56f25e569"
      tags = "DEMO, SCRIPT, T1090, T1105, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<tr><form method=post><td><font color=red><b>Back connect:</b></font></td><td><i" 
      $s1 = "$perl_proxy_scp = \"IyEvdXNyL2Jpbi9wZXJsICANCiMhL3Vzci91c2MvcGVybC81LjAwNC9iaW4v" 
      $s2 = "<tr><form method=post><td><font color=red><b>Backdoor:</b></font></td><td><input" 
   condition: 
      1 of them
}