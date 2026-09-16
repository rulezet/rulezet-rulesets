rule Webshell_ak74shell_php_php_RID3143 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file ak74shell.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:15:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$res .= '<td align=\"center\"><a href=\"'.$xshell.'?act=chmod&file='.$_SESSION[" 
      $s2 = "AK-74 Security Team Web Site: www.ak74-team.net" 
      $s3 = "$xshell" 
   condition: 
      2 of them
}