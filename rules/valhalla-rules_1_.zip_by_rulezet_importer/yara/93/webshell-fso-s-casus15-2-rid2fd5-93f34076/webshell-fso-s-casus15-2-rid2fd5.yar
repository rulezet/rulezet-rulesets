rule Webshell_FSO_s_casus15_2_RID2FD5 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file casus15.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:14:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "copy ( $dosya_gonder" 
   condition: 
      all of them
}