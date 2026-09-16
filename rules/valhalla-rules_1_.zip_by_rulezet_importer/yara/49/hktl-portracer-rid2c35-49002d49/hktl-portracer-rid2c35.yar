rule HKTL_PortRacer_RID2C35 : DEMO HKTL {
   meta:
      description = "Semiautomatically generated YARA rule on file PortRacer.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-07-01 09:39:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Auto Scroll BOTH Text Boxes" 
      $s4 = "Start/Stop Portscanning" 
      $s6 = "Auto Save LogFile by pressing STOP" 
   condition: 
      all of them
}