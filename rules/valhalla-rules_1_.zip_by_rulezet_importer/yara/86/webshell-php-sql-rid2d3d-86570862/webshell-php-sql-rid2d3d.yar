rule Webshell_PHP_sql_RID2D3D : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file sql.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:23:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$result=mysql_list_tables($db) or die (\"$h_error<b>\".mysql_error().\"</b>$f_" 
      $s4 = "print \"<a href=\\\"$_SERVER[PHP_SELF]?s=$s&login=$login&passwd=$passwd&" 
   condition: 
      all of them
}