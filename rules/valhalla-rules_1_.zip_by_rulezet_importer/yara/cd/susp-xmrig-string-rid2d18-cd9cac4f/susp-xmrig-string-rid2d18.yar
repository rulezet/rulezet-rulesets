rule SUSP_XMRIG_String_RID2D18 : DEMO EXE FILE SUSP xmrig {
   meta:
      description = "Detects a suspicious XMRIG crypto miner executable string in filr"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-12-28 10:17:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "eb18ae69f1511eeb4ed9d4d7bcdf3391a06768f384e94427f4fc3bd21b383127"
      tags = "DEMO, EXE, FILE, SUSP, xmrig"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "xmrig.exe" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and 1 of them
}