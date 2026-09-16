rule Webshell_webshell_cnseay_x_RID31B5 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file webshell-cnseay-x.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:34:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s9 = "$_F_F.='_'.$_P_P[5].$_P_P[20].$_P_P[13].$_P_P[2].$_P_P[19].$_P_P[8].$_P_" 
   condition: 
      all of them
}