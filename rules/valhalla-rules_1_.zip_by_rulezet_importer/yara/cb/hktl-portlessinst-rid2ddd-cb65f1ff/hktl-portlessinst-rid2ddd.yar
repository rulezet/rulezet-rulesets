rule HKTL_portlessinst_RID2DDD : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file portlessinst.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 10:50:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "Fail To Open Registry" 
      $s3 = "f<-WLEggDr\"" 
      $s6 = "oMemoryCreateP" 
   condition: 
      all of them
}