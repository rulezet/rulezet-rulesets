rule Virus_Hijack_Trojan_GenericKDZ_79663_100_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_100_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ce7e1b41582175d91dc724f634d4dd00c52e25f11c388fcec97db9911e805e3"

  strings:
    $s1 = "(sPLiT" fullword ascii
    $s2 = "YIRn{d" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}