rule HKTL_IP_Stealing_Utilities_RID30ED : DEMO HKTL {
   meta:
      description = "Semiautomatically generated YARA rule on file IP Stealing Utilities.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-07-01 13:00:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "DarkKnight" 
      $s9 = "IPStealerUtilities" 
   condition: 
      all of them
}