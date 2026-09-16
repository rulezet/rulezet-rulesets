rule HKTL_scanarator_RID2CD1 : DEMO HKTL {
   meta:
      description = "Semiautomatically generated YARA rule on file scanarator.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-07-01 10:05:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "GET /scripts/..%c0%af../winnt/system32/cmd.exe?/c+dir HTTP/1.0" 
   condition: 
      all of them
}