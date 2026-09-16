rule Webshell_fuckphpshell_php_RID3156 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file fuckphpshell.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:18:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$succ = \"Warning! " 
      $s1 = "Don`t be stupid .. this is a priv3 server, so take extra care!" 
      $s2 = "\\*=-- MEMBERS AREA --=*/" 
      $s3 = "preg_match('/(\\n[^\\n]*){' . $cache_lines . '}$/', $_SESSION['o" 
   condition: 
      2 of them
}