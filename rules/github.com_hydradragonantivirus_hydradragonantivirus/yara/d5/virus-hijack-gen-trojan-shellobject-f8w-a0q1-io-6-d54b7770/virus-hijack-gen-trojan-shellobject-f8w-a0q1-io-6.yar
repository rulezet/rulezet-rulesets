rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_a0q1_io_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@a0q1@io_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0178e9acf5440b612ac1c84da321da00d13786116d198c0b2277d6922d8117d"

  strings:
    $s1 = "1(or service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}