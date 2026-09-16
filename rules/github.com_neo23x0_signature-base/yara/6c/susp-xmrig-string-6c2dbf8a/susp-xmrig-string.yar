rule SUSP_XMRIG_String {
   meta:
      description = "Detects a suspicious XMRIG crypto miner executable string in filr"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-12-28"
      hash1 = "eb18ae69f1511eeb4ed9d4d7bcdf3391a06768f384e94427f4fc3bd21b383127"
      id = "8c6f3e6e-df2a-51b7-81b8-21cd33b3c603"
   strings:
      $x1 = "xmrig.exe" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and 1 of them
}