rule MAL_Debug_BDoor_RID2C66 : DEMO MAL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file BDoor.dll"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 09:47:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, MAL, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\\BDoor\\" 
      $s4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" 
   condition: 
      all of them
}