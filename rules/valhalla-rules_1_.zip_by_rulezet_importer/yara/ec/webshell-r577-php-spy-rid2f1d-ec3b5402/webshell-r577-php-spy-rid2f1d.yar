rule Webshell_r577_php_spy_RID2F1D : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files r577.php.php.txt, spy.php.php.txt, s.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:43:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "eed14de3907c9aa2550d95550d1a2d5f"
      hash2 = "817671e1bdc85e04cc3440bbd9288800"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "echo $te.\"<div align=center><textarea cols=35 name=db_query>\".(!empty($_POST['" 
      $s3 = "echo sr(45,\"<b>\".$lang[$language.'_text80'].$arrow.\"</b>\",\"<select name=db>" 
   condition: 
      1 of them
}