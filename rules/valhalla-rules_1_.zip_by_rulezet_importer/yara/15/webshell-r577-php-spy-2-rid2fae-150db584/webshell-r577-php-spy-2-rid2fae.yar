rule Webshell_r577_php_spy_2_RID2FAE : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files r577.php.php.txt, r57.php.php.txt, spy.php.php.txt, s.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:07:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "eddf7a8fde1e50a7f2a817ef7cece24f"
      hash2 = "eed14de3907c9aa2550d95550d1a2d5f"
      hash3 = "817671e1bdc85e04cc3440bbd9288800"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$res = mssql_query(\"select * from r57_temp_table\",$db);" fullword
      $s2 = "'eng_text30'=>'Cat file'," fullword
      $s3 = "@mssql_query(\"drop table r57_temp_table\",$db);" fullword
   condition: 
      1 of them
}