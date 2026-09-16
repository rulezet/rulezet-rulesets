rule HKTL_FeliksPack3___Scanners_ipscan_RID33EA : DEMO HKTL {
   meta:
      description = "Semiautomatically generated YARA rule on file ipscan.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-07-01 15:08:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "WCAP;}ECTED" 
      $s4 = "NotSupported" 
      $s6 = "SCAN.VERSION{_" 
   condition: 
      all of them
}