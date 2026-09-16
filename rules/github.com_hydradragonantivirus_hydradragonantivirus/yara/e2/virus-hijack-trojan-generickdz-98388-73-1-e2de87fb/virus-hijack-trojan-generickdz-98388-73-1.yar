rule Virus_Hijack_Trojan_GenericKDZ_98388_73_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_73_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7df0b13943d4c94ab4b465262380a8c3b3ed7ec2fa42c2b60b373ea32152512"

  strings:
    $s1 = "4(wels" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}