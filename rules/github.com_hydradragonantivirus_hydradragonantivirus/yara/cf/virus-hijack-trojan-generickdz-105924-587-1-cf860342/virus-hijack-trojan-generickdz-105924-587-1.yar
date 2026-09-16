rule Virus_Hijack_Trojan_GenericKDZ_105924_587_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_587_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91125a8fb3584d27f6bfbf2fe90afb57a9ff13178e32d59aca8cf3d65bc6fa73"

  strings:
    $s1 = "yday]vM" fullword ascii
    $s2 = ")`cLUe" fullword ascii
    $s3 = "scyT.]" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}