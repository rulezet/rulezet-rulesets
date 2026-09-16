rule Webshell_HYTop2006_rar_Folder_2006_RID32C8 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file 2006.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 14:19:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s6 = "strBackDoor = strBackDoor " 
   condition: 
      all of them
}