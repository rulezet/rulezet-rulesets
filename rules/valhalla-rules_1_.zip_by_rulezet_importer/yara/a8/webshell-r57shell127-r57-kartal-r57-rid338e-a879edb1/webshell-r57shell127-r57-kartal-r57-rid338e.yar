rule Webshell_r57shell127_r57_kartal_r57_RID338E : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files r57shell127.php, r57_kartal.php, r57.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 14:52:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "1d912c55b96e2efe8ca873d6040e3b30"
      hash2 = "4108f28a9792b50d95f95b9e5314fa1e"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "$handle = @opendir($dir) or die(\"Can't open directory $dir\");" fullword
      $s3 = "if(!empty($_POST['mysql_db'])) { @mssql_select_db($_POST['mysql_db'],$db); }" fullword
      $s5 = "if (!isset($_SERVER['PHP_AUTH_USER']) || $_SERVER['PHP_AUTH_USER']!==$name || $_" 
   condition: 
      2 of them
}