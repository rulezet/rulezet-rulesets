rule Virus_Hijack_Gen_Trojan_ShellObject_u8Z_aqOJzSd_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aqOJzSd_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "48ebd4de908e8271facf37e151b66509ddb94183d17376c3e9a8881fc418cc26"

  strings:
    $s1 = "QUiT%z" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}