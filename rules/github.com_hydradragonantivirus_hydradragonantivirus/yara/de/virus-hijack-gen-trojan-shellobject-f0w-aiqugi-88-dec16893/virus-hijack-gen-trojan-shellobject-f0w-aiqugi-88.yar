rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_88 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_88.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e0f2eec101f4a3a58afe8cf9cd1595fc9a81e10f1f3f55702124b429f0b024c"

  strings:
    $s1 = "e@4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}