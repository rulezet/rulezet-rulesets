rule Virus_Sysbot_Gen_Heur_ManBat_1_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Gen.Heur.ManBat.1_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "024b3a72cc3fec3586ede05ca8b034ba3ef6f96375c736d252d784ce64866906"

  strings:
    $s1 = "':stuG" fullword ascii
    $s2 = "twaT:]" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}