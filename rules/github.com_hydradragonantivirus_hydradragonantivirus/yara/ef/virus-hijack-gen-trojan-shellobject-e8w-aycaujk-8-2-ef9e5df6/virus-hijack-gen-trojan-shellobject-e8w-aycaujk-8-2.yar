rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aycAujk_8_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aycAujk_8_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b1c53fad1f72df03b65c7b9086c13849accb388289fc08034503c370b5429ad"

  strings:
    $s1 = "y}TriM" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}