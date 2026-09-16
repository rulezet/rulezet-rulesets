rule Webshell_php_backdoor_php_RID3139 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file php-backdoor.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:13:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "http://michaeldaw.org   2006" 
      $s1 = "or http://<? echo $SERVER_NAME.$REQUEST_URI; ?>?d=c:/windows on win" 
      $s3 = "coded by z0mbie" 
   condition: 
      1 of them
}