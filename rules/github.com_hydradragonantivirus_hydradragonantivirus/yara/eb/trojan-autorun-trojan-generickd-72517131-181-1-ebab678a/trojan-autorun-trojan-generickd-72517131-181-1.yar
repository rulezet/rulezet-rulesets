rule Trojan_Autorun_Trojan_GenericKD_72517131_181_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_181_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4535e7e0f3bbaacae2345f8c69fa8275d2347027cb1f1a811bfd1cb8548e301d"

  strings:
    $s1 = "^tUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}