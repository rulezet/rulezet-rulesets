rule HKTL_DllInjection_RID2D62 : DEMO HKTL T1055_001 T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file DllInjection.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 10:29:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1055_001, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "\\BDoor\\DllInjecti" 
   condition: 
      all of them
}