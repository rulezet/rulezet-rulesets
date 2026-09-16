rule Virus_Hijack_Trojan_GenericKDZ_79663_101_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_101_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1c047091c6ca6bc7b2e2c14d08ed3afa6a512a1fcf200ca6890101cc4facfcb"

  strings:
    $s1 = "2,niCk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}