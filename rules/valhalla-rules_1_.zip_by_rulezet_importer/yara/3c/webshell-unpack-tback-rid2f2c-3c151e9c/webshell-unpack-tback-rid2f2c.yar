rule Webshell_Unpack_TBack_RID2F2C : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file TBack.dll"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:45:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s5 = "\\final\\new\\lcc\\public.dll" 
   condition: 
      all of them
}