rule EquationGroup_Toolset_Apr17_EpWrapper {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "a8eed17665ee22198670e22458eb8c9028ff77130788f24f44986cce6cebff8d"
      id = "81b72f7f-ba5a-5f45-b77c-071cfb4571d3"
   strings:
      $x1 = "* Failed to get remote TCP socket address" fullword wide
      $x2 = "* Failed to get 'LPStart' export" fullword wide
      $s5 = "Usage: %ls <logdir> <dll_search_path> <dll_to_load_path> <socket>" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 20KB and 1 of them )
}