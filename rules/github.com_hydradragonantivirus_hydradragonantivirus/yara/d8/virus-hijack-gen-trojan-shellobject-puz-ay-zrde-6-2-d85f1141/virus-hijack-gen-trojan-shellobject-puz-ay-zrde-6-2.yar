rule Virus_Hijack_Gen_Trojan_ShellObject_puZ_ay_ZRde_6_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.puZ@ay!ZRde_6_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db03f8331bcecdee6eb242d97f5a06225558755ac722ea549b5887d24bea0364"

  strings:
    $s1 = "MASHy>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}