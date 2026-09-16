rule Trojan_Danger_Trojan_GenericKD_67166905_280_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_280_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e62cbe05b44381038b437e293fa31e19ca619957f637870e07ace185d768fc3"

  strings:
    $s1 = "(dispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}