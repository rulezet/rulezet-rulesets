rule HKTL_pwreveal_RID2C09 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file pwreveal.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 09:32:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "*<Blank - no es" 
      $s3 = "JDiamondCS " 
      $s8 = "sword set> [Leith=0 bytes]" 
      $s9 = "ION\\System\\Floating-" 
   condition: 
      all of them
}