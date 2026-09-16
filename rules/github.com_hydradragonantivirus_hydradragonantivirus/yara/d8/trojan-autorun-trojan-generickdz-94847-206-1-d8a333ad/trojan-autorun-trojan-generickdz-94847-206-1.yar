rule Trojan_Autorun_Trojan_GenericKDZ_94847_206_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_206_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eddc94708b4fdc7779f7a966124e9e2e9621cf48b4f77da294f6953d4ffe87e4"

  strings:
    $s1 = "and you and Oracle agree to submit to the exc`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}