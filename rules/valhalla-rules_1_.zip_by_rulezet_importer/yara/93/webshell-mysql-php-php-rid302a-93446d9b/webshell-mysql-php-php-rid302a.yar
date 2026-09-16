rule Webshell_mysql_php_php_RID302A : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file mysql.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:28:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "action=mysqlread&mass=loadmass\">load all defaults" 
      $s2 = "if (@passthru($cmd)) { echo \" -->\"; $this->output_state(1, \"passthru" 
      $s3 = "$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = " 
   condition: 
      1 of them
}