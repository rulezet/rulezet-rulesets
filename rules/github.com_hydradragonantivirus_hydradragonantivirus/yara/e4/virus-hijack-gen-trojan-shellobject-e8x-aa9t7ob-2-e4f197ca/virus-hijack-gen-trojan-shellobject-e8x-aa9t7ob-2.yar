rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aa9T7Ob_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aa9T7Ob_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cbc175fe78831558e5d84bbe88c958433af1dcba1a3971b6306d9ce4a792ed18"

  strings:
    $s1 = "Oxhundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}