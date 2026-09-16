rule Trojan_Autorun_Trojan_GenericKDZ_94847_74_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_74_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0de4442e1a7614eb8816e11f0d5156a2da068881a8ef51e46389b131850e2829"

  strings:
    $s1 = "AVwhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}