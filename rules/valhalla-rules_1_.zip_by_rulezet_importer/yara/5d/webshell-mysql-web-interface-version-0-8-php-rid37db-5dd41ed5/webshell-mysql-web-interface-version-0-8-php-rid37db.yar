rule Webshell_MySQL_Web_Interface_Version_0_8_php_RID37DB : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file MySQL Web Interface Version 0.8.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 17:56:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "SooMin Kim" 
      $s1 = "http://popeye.snu.ac.kr/~smkim/mysql" 
      $s2 = "href='$PHP_SELF?action=dropField&dbname=$dbname&tablename=$tablename" 
      $s3 = "<th>Type</th><th>&nbspM&nbsp</th><th>&nbspD&nbsp</th><th>unsigned</th><th>zerofi" 
   condition: 
      2 of them
}