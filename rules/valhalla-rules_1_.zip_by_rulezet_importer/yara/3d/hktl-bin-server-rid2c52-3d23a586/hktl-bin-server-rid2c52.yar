rule HKTL_BIN_Server_RID2C52 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file Server.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 09:44:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "configserver" 
      $s1 = "GetLogicalDrives" 
      $s2 = "WinExec" 
      $s4 = "fxftest" 
      $s5 = "upfileok" 
      $s7 = "upfileer" 
   condition: 
      all of them
}