rule Virus_Hijack_Gen_Trojan_ShellObject_4yZ_aSgChKg_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.4yZ@aSgChKg_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "771bf07cdae65da1256b218ced6c728c6d21e12ed3fb01283728f32a80e90e9b"

  strings:
    $s1 = "gram Files\\(7" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}