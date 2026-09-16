rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aG5Bc5o_15_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_15_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02d92594cc4673b514c2e72bd7652feae261db2fc1a11bfdf68d5b8ee6d41ce0"

  strings:
    $s1 = "Folder Cache" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}