rule EquationGroup_Toolset_Apr17_promiscdetect_safe {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "6070d8199061870387bb7796fb8ccccc4d6bafed6718cbc3a02a60c6dc1af847"
      id = "d6103861-b332-5c21-8408-76b512012689"
   strings:
      $s1 = "running on this computer!" fullword ascii
      $s2 = "- Promiscuous (capture all packets on the network)" fullword ascii
      $s3 = "Active filter for the adapter:" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 80KB and all of them )
}