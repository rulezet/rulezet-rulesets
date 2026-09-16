rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_304_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_304_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b829b1d15b4a9a0ba306f773c1da8f9e03ffc7365106a4a20a92e680644ef128"

  strings:
    $s1 = "microsoft.com/office/backup. You may not distribute the backup co" fullword ascii
    $s2 = "e option to convert your trial rights to subscription or" fullword ascii
    $s3 = "a third party without restriction on the " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}