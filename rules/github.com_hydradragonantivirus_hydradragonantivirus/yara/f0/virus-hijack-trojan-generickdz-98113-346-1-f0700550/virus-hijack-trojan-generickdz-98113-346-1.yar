rule Virus_Hijack_Trojan_GenericKDZ_98113_346_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_346_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf3f0b533442ef6ab9cc2fc4dbd0c443ce0eb01a15a9be90ac3c0ec2555b35e2"

  strings:
    $s1 = "IDEA>g$" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}