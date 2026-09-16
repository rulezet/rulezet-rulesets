rule EquationGroup_Toolset_Apr17_Windows_Implant {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "d38ce396926e45781daecd18670316defe3caf975a3062470a87c1d181a61374"
      id = "a82aac49-8843-5420-8b87-f3d7431bc63f"
   strings:
      $s2 = "0#0)0/050;0M0Y0h0|0" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 50KB and all of them )
}