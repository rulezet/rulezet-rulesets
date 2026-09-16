rule EquationGroup_Toolset_Apr17_Processes_Target {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "69cf7643dbecc5f9b4b29edfda6c0295bc782f0e438f19be8338426f30b4cc74"
      id = "1b910f46-5d19-5ecd-9647-10ee9ee7b012"
   strings:
      $s1 = "Select * from Win32_Process" fullword ascii
      $s3 = "\\\\%ls\\root\\cimv2" fullword wide
      $s5 = "%4ls%2ls%2ls%2ls%2ls%2ls.%11l[0-9]%1l[+-]%6s" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 2 of them )
}