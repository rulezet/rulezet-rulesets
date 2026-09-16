rule EquationGroup_Toolset_Apr17_Dsz_Implant {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "fbe103fac45abe4e3638055a3cac5e7009166f626cf2d3049fb46f3b53c1057f"
      hash2 = "ad1dddd11b664b7c3ad6108178a8dade0a6d9795358c4a7cedbe789c62016670"
      id = "febc8654-7dc3-5c8b-a53c-f8d7dc29b14b"
   strings:
      $s1 = "%02u:%02u:%02u.%03u-%4u: " fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and all of them )
}