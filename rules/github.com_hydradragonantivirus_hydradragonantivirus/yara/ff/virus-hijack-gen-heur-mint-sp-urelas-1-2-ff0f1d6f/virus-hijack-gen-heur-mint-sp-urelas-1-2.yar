rule Virus_Hijack_Gen_Heur_Mint_SP_Urelas_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Heur.Mint.SP.Urelas.1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "093c1ada84105e4fe1fe9dc46cfe002397d2a5ceec24ee2a796fe6d908eec002"

  strings:
    $s1 = "Xiphias" fullword wide
    $s2 = "Unwifely" fullword wide
    $s3 = "Reoccurrence" fullword wide
    $s4 = ")>0-$)7&'$8:1@$$Dite" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}