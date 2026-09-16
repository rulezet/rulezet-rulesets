rule Virus_Hijack_Trojan_GenericKDZ_74550_121_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_121_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "739455cfcfaf33efe8611d76de0b64a181d851a88de8b8adb77d19b53d87c08a"

  strings:
    $s1 = " LACK&Gc" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}