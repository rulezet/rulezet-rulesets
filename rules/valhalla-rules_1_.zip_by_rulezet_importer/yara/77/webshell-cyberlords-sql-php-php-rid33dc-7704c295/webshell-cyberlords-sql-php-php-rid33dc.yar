rule Webshell_cyberlords_sql_php_php_RID33DC : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file cyberlords_sql.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 15:05:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Coded by n0 [nZer0]" 
      $s1 = " www.cyberlords.net" 
      $s2 = "U29mdHdhcmUAQWRvYmUgSW1hZ2VSZWFkeXHJZTwAAAAMUExURf///wAAAJmZzAAAACJoURkAAAAE" 
      $s3 = "return \"<BR>Dump error! Can't write to \".htmlspecialchars($file);" 
   condition: 
      1 of them
}