rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_32 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_32.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24616a842d13b0f509794648f0ffe626f540cc8c327151723a763abb29252129"

  strings:
    $s1 = "h4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}