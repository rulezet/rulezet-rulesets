rule Virus_Hijack_Trojan_GenericKDZ_98388_190_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_190_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "575ff63d1a96c8e2d4437bb75f603832400977c0fa50113f974f57ef0a74e65e"

  strings:
    $s1 = ")mANG`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}