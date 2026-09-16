rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_ae3yXvm_11 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68ff5103dd571292abcce62edd7d90e09e2f09e1e4703f1cf2a2f81d682a48d7"

  strings:
    $s1 = "Sr4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}