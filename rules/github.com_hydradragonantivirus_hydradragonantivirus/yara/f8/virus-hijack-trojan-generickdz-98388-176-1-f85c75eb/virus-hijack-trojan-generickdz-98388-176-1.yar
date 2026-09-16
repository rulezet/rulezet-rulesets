rule Virus_Hijack_Trojan_GenericKDZ_98388_176_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_176_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90ff0d9f119f25d144d37ad2fec3e6c74bfafa6631164fb8f7e943446b2ad482"

  strings:
    $s1 = "voLt]:" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}