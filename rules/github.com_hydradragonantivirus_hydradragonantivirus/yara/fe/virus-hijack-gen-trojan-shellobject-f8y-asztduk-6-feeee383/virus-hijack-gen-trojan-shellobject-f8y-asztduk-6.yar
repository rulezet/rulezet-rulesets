rule Virus_Hijack_Gen_Trojan_ShellObject_f8Y_aSZtDuk_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aSZtDuk_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d61e45fa39a5ffd482499a6bae2b1e05a3b32561bd72a96891ca80c764171014"

  strings:
    $s1 = "Tor service that is subject to a discount or a pr" fullword ascii
    $s2 = "wOOM{M" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}