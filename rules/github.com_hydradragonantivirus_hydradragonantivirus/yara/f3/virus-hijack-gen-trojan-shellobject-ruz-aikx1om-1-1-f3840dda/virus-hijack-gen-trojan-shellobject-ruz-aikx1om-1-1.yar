rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_aikx1Om_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@aikx1Om_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4a311be291b320836b85cae8d010002639241b2bc22c242213a64cf6d659e74f"

  strings:
    $s1 = "@:CUrl" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}