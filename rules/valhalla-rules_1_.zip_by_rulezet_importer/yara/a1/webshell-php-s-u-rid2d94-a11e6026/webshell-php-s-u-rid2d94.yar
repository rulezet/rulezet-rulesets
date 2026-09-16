rule Webshell_php_s_u_RID2D94 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file s-u.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:37:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s6 = "<a href=\"?act=do\"><font color=\"red\">Go Execute</font></a></b><br /><textarea" 
   condition: 
      all of them
}