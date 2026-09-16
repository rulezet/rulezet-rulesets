rule HKTL_SetupBDoor_RID2C8A : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file SetupBDoor.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 09:53:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\\BDoor\\SetupBDoor" 
   condition: 
      all of them
}