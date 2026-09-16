rule HKTL_bdcli100_RID2B32 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file bdcli100.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 08:56:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s5 = "unable to connect to " 
      $s8 = "backdoor is corrupted on " 
   condition: 
      all of them
}