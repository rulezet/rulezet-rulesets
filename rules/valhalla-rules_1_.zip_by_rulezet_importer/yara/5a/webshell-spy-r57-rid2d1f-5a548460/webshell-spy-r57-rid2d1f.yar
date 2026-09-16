rule Webshell_Spy_r57_RID2D1F : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files r577.php.php.txt, r57 Shell.php.php.txt, spy.php.php.txt, s.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 10:18:21"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "8023394542cddf8aee5dec6072ed02b5"
      hash2 = "eed14de3907c9aa2550d95550d1a2d5f"
      hash3 = "817671e1bdc85e04cc3440bbd9288800"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "echo ws(2).$lb.\" <a" 
      $s1 = "$sql = \"LOAD DATA INFILE \\\"\".$_POST['test3_file']" 
      $s3 = "if (empty($_POST['cmd'])&&!$safe_mode) { $_POST['cmd']=($windows)?(\"dir\"):(\"l" 
   condition: 
      2 of them
}