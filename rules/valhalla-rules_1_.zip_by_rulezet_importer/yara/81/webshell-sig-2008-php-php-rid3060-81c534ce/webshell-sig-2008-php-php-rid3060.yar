rule Webshell_sig_2008_php_php_RID3060 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file 2008.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:37:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Codz by angel(4ngel)" 
      $s1 = "Web: http://www.4ngel.net" 
      $s2 = "$admin['cookielife'] = 86400;" 
      $s3 = "$errmsg = 'The file you want Downloadable was nonexistent';" 
   condition: 
      1 of them
}