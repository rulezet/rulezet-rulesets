rule HKTL_hkshell_hkrmv_RID2E15 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file hkrmv.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 10:59:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s5 = "/THUMBPOSITION7" 
      $s6 = "\\EvilBlade\\" 
   condition: 
      all of them
}