rule Virus_Hijack_Gen_Trojan_ShellObject_3yZ_aWcfH4h_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.3yZ@aWcfH4h_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5cadb0f722de2c4420b1e85fa4ddfaef7c155a5e19036fd314b436d08b7ba18f"

  strings:
    $s1 = "arnI coI" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}