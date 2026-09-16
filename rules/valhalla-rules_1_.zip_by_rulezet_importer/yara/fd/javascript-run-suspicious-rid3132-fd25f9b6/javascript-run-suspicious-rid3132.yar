rule JavaScript_Run_Suspicious_RID3132 : DEMO SCRIPT T1059 {
   meta:
      description = "Detects a suspicious Javascript Run command"
      author = "Florian Roth"
      reference = "https://twitter.com/craiu/status/900314063560998912"
      date = "2017-08-23 13:12:11"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1059"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "w = new ActiveXObject(" ascii
      $s2 = " w.Run(r);" fullword ascii
   condition: 
      all of them
}