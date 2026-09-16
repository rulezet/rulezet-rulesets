rule VirusShareTrojanInject417716 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanInject417716.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8aaa4ca5326fac5f00af5beb36e12aa8091f5b59fc6a845403512fe78dbaeeb"

  strings:
    $s1 = "HeapAlloc error" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}