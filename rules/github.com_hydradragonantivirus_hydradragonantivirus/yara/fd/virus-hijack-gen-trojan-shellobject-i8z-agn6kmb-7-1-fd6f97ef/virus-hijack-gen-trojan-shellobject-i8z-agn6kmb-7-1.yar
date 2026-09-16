rule Virus_Hijack_Gen_Trojan_ShellObject_i8Z_aGN6KMb_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Z@aGN6KMb_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e74ee04a6e247cc3e6fb77cf2794af392afa68b864f62141157c7b9e1f4677a"

  strings:
    $s1 = "!Error Download" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}