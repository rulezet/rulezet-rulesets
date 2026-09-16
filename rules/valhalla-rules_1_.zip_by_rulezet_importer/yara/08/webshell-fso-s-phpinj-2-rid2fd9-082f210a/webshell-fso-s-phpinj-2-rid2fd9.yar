rule Webshell_FSO_s_phpinj_2_RID2FD9 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file phpinj.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:14:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s9 = "<? system(\\$_GET[cpc]);exit; ?>' ,0 ,0 ,0 ,0 INTO" 
   condition: 
      all of them
}