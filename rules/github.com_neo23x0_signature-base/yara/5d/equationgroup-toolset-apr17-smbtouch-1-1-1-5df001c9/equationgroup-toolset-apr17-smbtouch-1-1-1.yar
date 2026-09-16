rule EquationGroup_Toolset_Apr17_Smbtouch_1_1_1 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "108243f61c53f00f8f1adcf67c387a8833f1a2149f063dd9ef29205c90a3c30a"
      id = "225799cf-4d1b-54f8-8b76-b9ee1db80ce7"
   strings:
      $x1 = "[+] Target is vulnerable to %d exploit%s" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and all of them )
}