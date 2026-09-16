rule Webshell_FSO_s_phvayv_RID2F5D : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file phvayv.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:54:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "wrap=\"OFF\">XXXX</textarea></font><font face" 
   condition: 
      all of them
}