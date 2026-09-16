rule Webshell_FSO_s_zehir4_2_RID2FA6 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file zehir4.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:06:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "\"Program Files\\Serv-u\\Serv" 
   condition: 
      all of them
}