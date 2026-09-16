rule Webshell_PHP_g00nv13_RID2DFC : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file g00nv13.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:55:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "case \"zip\": case \"tar\": case \"rar\": case \"gz\": case \"cab\": cas" 
      $s4 = "if(!($sqlcon = @mysql_connect($_SESSION['sql_host'] . ':' . $_SESSION['sql_p" 
   condition: 
      all of them
}