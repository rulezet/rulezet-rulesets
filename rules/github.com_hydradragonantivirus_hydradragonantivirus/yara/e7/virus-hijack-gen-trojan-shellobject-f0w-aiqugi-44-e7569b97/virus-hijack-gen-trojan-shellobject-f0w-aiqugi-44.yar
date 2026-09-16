rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_44 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_44.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "289f5b420d0308437b5c8155ebbe5f1d62f92743f5e6418751fe983efc59cb35"

  strings:
    $s1 = "X4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}