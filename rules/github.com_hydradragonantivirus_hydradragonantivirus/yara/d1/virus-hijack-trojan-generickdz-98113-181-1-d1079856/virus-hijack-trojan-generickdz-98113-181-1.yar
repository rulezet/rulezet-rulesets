rule Virus_Hijack_Trojan_GenericKDZ_98113_181_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_181_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "807536f9551bc0d3b468d32c30695f7851b78bb0f6db4ed82142b2c1163c7d85"

  strings:
    $s1 = "U]SAkE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}