rule HKTL_byshell063_ntboot_2_RID2FB5 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file ntboot.dll"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:08:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s6 = "OK,job was done,cuz we have localsystem & SE_DEBUG_NAME:)" 
   condition: 
      all of them
}