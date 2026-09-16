rule Webshell_FSO_s_phvayv_2_RID2FEE : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file phvayv.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:18:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "rows=\"24\" cols=\"122\" wrap=\"OFF\">XXXX</textarea></font><font" 
   condition: 
      all of them
}