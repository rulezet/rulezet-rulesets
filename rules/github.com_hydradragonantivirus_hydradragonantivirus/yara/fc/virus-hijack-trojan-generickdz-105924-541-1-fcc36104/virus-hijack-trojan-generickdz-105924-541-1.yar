rule Virus_Hijack_Trojan_GenericKDZ_105924_541_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_541_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0e23e2b49cde1e60b27720e49fd31e6706fc82d35783d314b746ab9d87a61ab"

  strings:
    $s1 = "&dEEM&C" fullword ascii
    $s2 = "!uVal$" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}