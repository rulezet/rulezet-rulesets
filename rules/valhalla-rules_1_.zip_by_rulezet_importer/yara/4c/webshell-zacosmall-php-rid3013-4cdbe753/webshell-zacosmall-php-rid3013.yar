rule Webshell_zacosmall_php_RID3013 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file zacosmall.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:24:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "rand(1,99999);$sj98" 
      $s1 = "$dump_file.='`'.$rows2[0].'`" 
      $s3 = "filename=\\\"dump_{$db_dump}_${table_d" 
   condition: 
      2 of them
}