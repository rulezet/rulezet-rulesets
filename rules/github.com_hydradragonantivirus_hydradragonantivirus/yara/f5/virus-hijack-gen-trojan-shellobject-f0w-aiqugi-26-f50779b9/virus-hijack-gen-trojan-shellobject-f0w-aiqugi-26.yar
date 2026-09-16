rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_26 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_26.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab948b33cf2d5b22ff0ed204b2660c61438fa78b579ae0b59084cc71f2a207ce"

  strings:
    $s1 = "a4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}