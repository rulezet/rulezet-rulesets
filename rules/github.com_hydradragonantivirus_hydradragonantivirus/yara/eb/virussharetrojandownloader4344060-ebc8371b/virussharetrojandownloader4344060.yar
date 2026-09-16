rule VirusShareTrojanDownLoader4344060 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanDownLoader4344060.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c747016e7b0c5c01115673bb337c68ebe32caf4838417fdc1f63e028a869a68"

  strings:
    $s1 = "Java(TM) Platform SE 8 U301" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}