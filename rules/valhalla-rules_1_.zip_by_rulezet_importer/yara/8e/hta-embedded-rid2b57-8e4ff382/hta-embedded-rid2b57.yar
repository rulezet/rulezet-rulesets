rule HTA_Embedded_RID2B57 : DEMO SUSP {
   meta:
      description = "Detects an embedded HTA file"
      author = "Florian Roth"
      reference = "https://twitter.com/msftmmpc/status/877396932758560768"
      date = "2017-06-21 09:02:21"
      score = 50
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ca7b653cf41e980c44311b2cd701ed666f8c1dbc"
      tags = "DEMO, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<hta:application windowstate=\"minimize\"/>" 
   condition: 
      $s1 and not $s1 in ( 0 .. 50000 )
}