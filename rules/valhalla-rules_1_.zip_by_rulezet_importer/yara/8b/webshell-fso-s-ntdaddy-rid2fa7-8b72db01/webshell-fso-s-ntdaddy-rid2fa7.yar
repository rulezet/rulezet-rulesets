rule Webshell_FSO_s_ntdaddy_RID2FA7 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file ntdaddy.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:06:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<input type=\"text\" name=\".CMD\" size=\"45\" value=\"<%= szCMD %>\"> <input type=\"s" 
   condition: 
      all of them
}