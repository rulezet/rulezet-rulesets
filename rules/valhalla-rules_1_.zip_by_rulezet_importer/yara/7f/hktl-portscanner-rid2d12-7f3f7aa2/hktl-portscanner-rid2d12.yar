rule HKTL_PortScanner_RID2D12 : DEMO HKTL {
   meta:
      description = "Semiautomatically generated YARA rule on file PortScanner.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-07-01 10:16:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Scan Ports Every" 
      $s3 = "Scan All Possible Ports!" 
   condition: 
      all of them
}