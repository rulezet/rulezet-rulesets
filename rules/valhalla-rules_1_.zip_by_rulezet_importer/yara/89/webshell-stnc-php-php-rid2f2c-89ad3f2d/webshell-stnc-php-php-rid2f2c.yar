rule Webshell_STNC_php_php_RID2F2C : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file STNC.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:45:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "drmist.ru" fullword
      $s1 = "hidden(\"action\",\"download\").hidden_pwd().\"<center><table><tr><td width=80" 
      $s2 = "STNC WebShell" 
      $s3 = "http://www.security-teams.net/index.php?showtopic=" 
   condition: 
      1 of them
}