rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aaajMem_29 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aaajMem_29.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7af379be4354f32c3a65154dd5b493d196b3459b9f4e04ac3e704af0614cc1e1"

  strings:
    $s1 = "dWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}