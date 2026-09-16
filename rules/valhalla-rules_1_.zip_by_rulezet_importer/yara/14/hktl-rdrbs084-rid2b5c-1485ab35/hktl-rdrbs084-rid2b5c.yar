rule HKTL_rdrbs084_RID2B5C : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file rdrbs084.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 09:03:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Create mapped port. You have to specify domain when using HTTP type." 
      $s8 = "<LOCAL PORT> <MAPPING SERVER> <MAPPING SERVER PORT> <TARGET SERVER> <TARGET" 
   condition: 
      all of them
}