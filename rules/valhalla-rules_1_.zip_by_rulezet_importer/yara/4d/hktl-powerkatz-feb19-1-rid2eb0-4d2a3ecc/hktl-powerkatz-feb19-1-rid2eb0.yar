rule HKTL_PowerKatz_Feb19_1_RID2EB0 : DEMO HKTL powerkatz {
   meta:
      description = "Detetcs a tool used in the Australian Parliament House network compromise"
      author = "Florian Roth"
      reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
      date = "2019-02-18 11:25:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, powerkatz"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Powerkatz32" ascii wide fullword
      $x2 = "Powerkatz64" ascii wide
      $s1 = "GetData: not found taskName" fullword ascii wide
      $s2 = "GetRes Ex:" fullword ascii wide
   condition: 
      1 of ( $x* ) and 1 of ( $s* )
}