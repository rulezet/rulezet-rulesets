rule HKTL_Mithril_v1_45_dllTest_RID3085 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file dllTest.dll"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:43:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "syspath" 
      $s4 = "\\Mithril" 
      $s5 = "--list the services in the computer" 
   condition: 
      all of them
}