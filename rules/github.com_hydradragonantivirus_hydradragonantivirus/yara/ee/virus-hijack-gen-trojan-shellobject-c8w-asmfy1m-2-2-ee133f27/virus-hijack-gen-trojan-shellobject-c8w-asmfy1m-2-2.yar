rule Virus_Hijack_Gen_Trojan_ShellObject_C8W_aSmFy1m_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.C8W@aSmFy1m_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4d7b5bdcc7bf2e81c5e597e7db500855309388a0c51fd8791a74936472bc235"

  strings:
    $s1 = "p$VAnG(" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}