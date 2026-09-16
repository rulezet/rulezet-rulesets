rule Virus_Hijack_Gen_Trojan_ShellObject_pzZ_aCEmdoo_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.pzZ@aCEmdoo_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac754487e1fc2f799594f992a07ed3bd85a949f531a80316bd095468e1c9fb6e"

  strings:
    $s1 = "MASHy>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}