rule Virus_Hijack_Gen_Trojan_ShellObject_j8Z_a0q1_io_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j8Z@a0q1@io_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bcb041342ee2720d2c1d9f6366b979509b32c9b6051c947ee14e2bc0e8c408fb"

  strings:
    $s1 = "0Vor service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}