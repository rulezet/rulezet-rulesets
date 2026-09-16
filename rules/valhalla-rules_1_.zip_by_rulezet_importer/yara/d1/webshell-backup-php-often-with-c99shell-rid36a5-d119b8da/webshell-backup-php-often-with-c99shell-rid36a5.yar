rule Webshell_backup_php_often_with_c99shell_RID36A5 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file backup.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 17:04:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "#phpMyAdmin MySQL-Dump" fullword
      $s2 = ";db_connect();header('Content-Type: application/octetstr" 
      $s4 = "$data .= \"#Database: $database" fullword
   condition: 
      all of them
}