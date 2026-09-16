rule Webshell_r577_php_RID2D62 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files r577.php.php.txt, r57.php.php.txt, r57 Shell.php.php.txt, spy.php.php.txt, s.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 10:29:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "eddf7a8fde1e50a7f2a817ef7cece24f"
      hash2 = "8023394542cddf8aee5dec6072ed02b5"
      hash3 = "eed14de3907c9aa2550d95550d1a2d5f"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "if(rmdir($_POST['mk_name']))" 
      $s2 = "$r .= '<tr><td>'.ws(3).'<font face=Verdana size=-2><b>'.$key.'</b></font></td>" 
      $s3 = "if(unlink($_POST['mk_name'])) echo \"<table width=100% cellpadding=0 cell" 
   condition: 
      2 of them
}