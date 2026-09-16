rule Trojan_Hooker_Trojan_GenericKD_32091152 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Trojan.GenericKD.32091152.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce98cd3e874ce0337306aabb24396dbe4ce0b1545ae9846d7baa4a2c06f71f34"

  strings:
    $s1 = "Java SE Binary" fullword wide
    $s2 = ")CoED'a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}