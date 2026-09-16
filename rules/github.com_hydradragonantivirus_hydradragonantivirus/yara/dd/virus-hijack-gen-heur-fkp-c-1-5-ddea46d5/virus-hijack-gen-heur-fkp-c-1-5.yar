rule Virus_Hijack_Gen_Heur_FKP__c__1_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Heur.FKP.!c!.1_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b2371d80a6370ecfac4fa7198ac601721f7a27df136748ca57508264f275ebf"

  strings:
    $s1 = "lithomancy" fullword wide
    $s2 = "Astroblast" fullword wide
    $s3 = "Submeaning" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}