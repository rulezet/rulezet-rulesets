rule HKTL_Debug_cress_RID2D09 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file cress.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 10:14:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "\\Mithril " 
      $s4 = "Mithril.exe" 
   condition: 
      all of them
}