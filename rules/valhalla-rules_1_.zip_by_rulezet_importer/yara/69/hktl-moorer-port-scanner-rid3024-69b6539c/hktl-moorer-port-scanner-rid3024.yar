rule HKTL_MooreR_Port_Scanner_RID3024 : DEMO HKTL T1046 {
   meta:
      description = "Semiautomatically generated YARA rule on file MooreR Port Scanner.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-07-01 12:27:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1046"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Description|" 
      $s3 = "soft Visual Studio\\VB9yp" 
      $s4 = "adj_fptan?4" 
      $s7 = "DOWS\\SyMem32\\/o" 
   condition: 
      all of them
}