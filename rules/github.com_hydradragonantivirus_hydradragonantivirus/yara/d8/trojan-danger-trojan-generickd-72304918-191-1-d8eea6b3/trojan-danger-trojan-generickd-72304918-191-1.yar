rule Trojan_Danger_Trojan_GenericKD_72304918_191_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_191_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96adc6791c54f3c41969d9bd83302e1a60e8206a2302ef6a8a83352e1ce6282d"

  strings:
    $s1 = "s&message dialog." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}