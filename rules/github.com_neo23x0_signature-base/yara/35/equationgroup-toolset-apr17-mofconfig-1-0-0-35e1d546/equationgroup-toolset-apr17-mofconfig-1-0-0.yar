rule EquationGroup_Toolset_Apr17_Mofconfig_1_0_0 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "c67a24fe2380331a101d27d6e69b82d968ccbae54a89a2629b6c135436d7bdb2"
      id = "d0d32e19-d004-5941-a5b3-0b4306565cf2"
   strings:
      $x1 = "[-] Get RemoteMOFTriggerPath error" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 50KB and all of them )
}