rule Webshell_sql_php_php_RID2F44 : DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file sql.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:49:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2025-07-04"
      tags = "DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "fputs ($fp, \"# RST MySQL tools\\r\\n# Home page: http://rst.void.ru\\r\\n#" 
      $s2 = "http://rst.void.ru" 
      $s3 = "print \"<a href=\\\"$_SERVER[PHP_SELF]?s=$s&login=$login&passwd=$passwd&" 
   condition: 
      1 of them and not uint32 ( 0 ) == 0x6D783F3C
}