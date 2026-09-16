rule Webshell_mysql_shell_php_RID30FA : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file mysql_shell.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:02:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "SooMin Kim" 
      $s1 = "smkim@popeye.snu.ac.kr" 
      $s2 = "echo \"<td><a href='$PHP_SELF?action=deleteData&dbname=$dbname&tablename=$tablen" 
   condition: 
      1 of them
}