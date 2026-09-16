rule Virus_Hijack_Gen_Trojan_ShellObject_h8X_a0kuefc_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.h8X@a0kuefc_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dac8bf2a673f203f9ee1bdec507a53eae283e540273b1875037e37fcb6210809"

  strings:
    $s1 = "Kavirtualization, see the Additional Terms." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}