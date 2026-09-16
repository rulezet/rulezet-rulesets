rule EquationGroup_Toolset_Apr17_promiscdetect_safe_RID396A : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 19:02:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "6070d8199061870387bb7796fb8ccccc4d6bafed6718cbc3a02a60c6dc1af847"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "running on this computer!" fullword ascii
      $s2 = "- Promiscuous (capture all packets on the network)" fullword ascii
      $s3 = "Active filter for the adapter:" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 80KB and all of them )
}