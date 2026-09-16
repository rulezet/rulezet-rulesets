rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aG5Bc5o_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3fcafc2e3194c97e8d330a1f5f46028ad109b575e5b29a591a37f5ab67c71e34"

  strings:
    $s1 = "NOhundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}