rule HKTL_Mithril_v1_45_Mithril_RID3082 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file Mithril.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:42:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "cress.exe" 
      $s7 = "\\Debug\\Mithril." 
   condition: 
      all of them
}