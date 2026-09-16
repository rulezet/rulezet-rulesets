rule Virus_Hijack_Trojan_Peed_Gen_54_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Peed.Gen_54_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ceb2d5d77a9df4b2f6a5d0751e6150a12e54bb6494c6fee06d55c63ec3a23147"

  strings:
    $s1 = "uNdy}o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}