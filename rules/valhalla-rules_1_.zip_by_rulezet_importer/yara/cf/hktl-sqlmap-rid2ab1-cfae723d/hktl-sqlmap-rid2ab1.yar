rule HKTL_SQLMap_RID2AB1 : DEMO HKTL {
   meta:
      description = "This signature detects the SQLMap SQL injection tool"
      author = "Florian Roth"
      reference = "-"
      date = "2014-07-01 07:46:41"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "except SqlmapBaseException, ex:" 
   condition: 
      1 of them
}