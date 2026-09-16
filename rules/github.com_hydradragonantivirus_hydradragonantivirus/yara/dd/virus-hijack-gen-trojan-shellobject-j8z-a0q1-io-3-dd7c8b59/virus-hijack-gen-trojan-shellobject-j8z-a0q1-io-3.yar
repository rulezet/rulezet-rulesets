rule Virus_Hijack_Gen_Trojan_ShellObject_j8Z_a0q1_io_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j8Z@a0q1@io_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44c67fce89739f7a98057d3c7d2e14e870666d60477b896e2ee6546b0c2ffe9b"

  strings:
    $s1 = "~or service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}