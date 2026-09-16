rule Virus_Hijack_Gen_Trojan_ShellObject_q8Z_aSQPfVg_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aSQPfVg_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81b6a09c481f4e689a9c8afc9d72d1e9b700996b46acaebffbabc1f05372311e"

  strings:
    $s1 = "<Silt*%I" fullword ascii
    $s2 = "IIwI {VT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}