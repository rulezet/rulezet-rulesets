rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aa9T7Ob_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aa9T7Ob_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2288fb28416287eed4d1ec180e22732270b75376d32910c937ecbdca40eff091"

  strings:
    $s1 = "<hundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}