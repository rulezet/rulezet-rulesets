rule Trojan_Autorun_Gen_Trojan_Heur_D_cmIfbi3RsP_8_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Trojan.Heur.D.cmIfbi3RsP_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fcb9468562f3d311150de38c9e8a81563015a30baa98004b5c6216dd0c57e65e"

  strings:
    $s1 = "Eor service that is subject to a discount or a pr" fullword ascii
    $s2 = "naam%aa" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}