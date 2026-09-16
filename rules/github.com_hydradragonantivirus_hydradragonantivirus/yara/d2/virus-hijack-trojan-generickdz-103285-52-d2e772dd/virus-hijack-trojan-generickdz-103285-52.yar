rule Virus_Hijack_Trojan_GenericKDZ_103285_52 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_52.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "77a194298867d943cf6c48079bbf3343453bee62c50590a48be776a5bf2c97ed"

  strings:
    $s1 = "and/or running. With respect to the Customer Data Hub program, in determining the number `" fullword ascii
    $s2 = "nmust be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}