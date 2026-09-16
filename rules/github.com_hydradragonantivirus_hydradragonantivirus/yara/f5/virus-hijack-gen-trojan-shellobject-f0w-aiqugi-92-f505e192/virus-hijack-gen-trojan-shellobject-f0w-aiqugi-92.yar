rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_92 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_92.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c523d6b63b7917963b20303216e032f332b399b306114ae035b7936c1758441"

  strings:
    $s1 = "L4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}