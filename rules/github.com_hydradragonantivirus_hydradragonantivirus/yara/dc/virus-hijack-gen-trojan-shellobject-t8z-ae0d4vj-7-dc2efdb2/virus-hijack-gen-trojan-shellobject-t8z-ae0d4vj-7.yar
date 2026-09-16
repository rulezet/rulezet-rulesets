rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_ae0D4Vj_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@ae0D4Vj_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94da25b9c03b9332df794d369c2a7b8d0c028af55288bc6eaacb2faa757b9b5f"

  strings:
    $s1 = "FXa neutral arbitrator, whose decision will be final except for a limited right of appeal under the Federal" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}