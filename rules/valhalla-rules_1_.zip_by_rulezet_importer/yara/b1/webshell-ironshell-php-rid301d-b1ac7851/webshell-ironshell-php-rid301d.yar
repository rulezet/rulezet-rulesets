rule Webshell_ironshell_php_RID301D : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file ironshell.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:26:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "www.ironwarez.info" 
      $s1 = "$cookiename = \"wieeeee\";" 
      $s2 = "~ Shell I" 
      $s3 = "www.rootshell-team.info" 
      $s4 = "setcookie($cookiename, $_POST['pass'], time()+3600);" 
   condition: 
      1 of them
}