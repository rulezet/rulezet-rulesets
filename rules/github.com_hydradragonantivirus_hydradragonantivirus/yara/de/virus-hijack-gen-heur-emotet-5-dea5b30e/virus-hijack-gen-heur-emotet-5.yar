rule Virus_Hijack_Gen_Heur_Emotet_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Heur.Emotet.5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f23d88e24681504c5cd62af2c072f91c38007563d278f6da9dc1162ab982c556"

  strings:
    $s1 = "dropflower" fullword wide
    $s2 = "textilist" fullword wide
    $s3 = "Unbasedness" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}