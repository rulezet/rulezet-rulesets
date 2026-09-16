rule Virus_Hijack_Gen_Trojan_ShellObject_eyY_aOWVavp_15_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eyY@aOWVavp_15_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c679019554ba841be68f5947eafa8b66f3755138a52cea3aff3d545e6ae5e51b"

  strings:
    $s1 = "Rich#44" fullword ascii
    $s2 = "E?peRn" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}