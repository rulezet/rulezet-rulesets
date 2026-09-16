rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_90 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_90.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55d8fb1fa62f7f1ac69dee544e878fc33921a6d92d9ae6f9f3dbf364c4cb949a"

  strings:
    $s1 = "Ee%J_q%HOng@X#dFIlpK^p+%kp%UKqq" fullword ascii
    $s2 = "K4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}