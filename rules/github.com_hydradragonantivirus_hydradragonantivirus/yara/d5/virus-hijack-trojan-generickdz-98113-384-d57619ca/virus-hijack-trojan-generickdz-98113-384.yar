rule Virus_Hijack_Trojan_GenericKDZ_98113_384 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_384.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef1ab7afbcfc02fa58db5f349848dab1f7105e44b8645749a265fc90cdb19ce8"

  strings:
    $s1 = "envy#g" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}