rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_58 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_58.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73b5b3cf9304445ae7aee1ecce795b2af5a767168451d6ae9c4df1500069a025"

  strings:
    $s1 = "E4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}