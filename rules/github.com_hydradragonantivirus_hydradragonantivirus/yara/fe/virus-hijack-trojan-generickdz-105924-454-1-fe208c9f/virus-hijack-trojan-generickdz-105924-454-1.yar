rule Virus_Hijack_Trojan_GenericKDZ_105924_454_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_454_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ff14db70e2f4afd578b41a42d6ef665ffa472b959f91c66d728b7164c04710f"

  strings:
    $s1 = "JEeR[\\" fullword ascii
    $s2 = "donG@YKbL" fullword ascii
    $s3 = "x@?touG" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}