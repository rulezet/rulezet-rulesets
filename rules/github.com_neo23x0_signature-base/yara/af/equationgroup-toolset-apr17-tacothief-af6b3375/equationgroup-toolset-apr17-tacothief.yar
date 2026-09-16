rule EquationGroup_Toolset_Apr17_tacothief {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "c71953cc84c27dc61df8f6f452c870a7880a204e9e21d9fd006a5c023b052b35"
      id = "7be7ca05-c2c7-5a7d-8b1b-e6741b4397b9"
   strings:
      $x1 = "File too large!  Must be less than 655360 bytes." fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and all of them )
}