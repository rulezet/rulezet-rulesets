rule HKTL_SqlMap_RID2AF1 : DEMO HKTL {
   meta:
      description = "Detects sqlmap hacktool"
      author = "Florian Roth"
      reference = "https://github.com/sqlmapproject/sqlmap"
      date = "2018-10-09 09:33:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9444478b03caf7af853a64696dd70083bfe67f76aa08a16a151c00aadb540fa8"
      tags = "DEMO, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "if cmdLineOptions.get(\"sqlmapShell\"):" fullword ascii
      $x2 = "if conf.get(\"dumper\"):" fullword ascii
   condition: 
      filesize < 50KB and 1 of them
}