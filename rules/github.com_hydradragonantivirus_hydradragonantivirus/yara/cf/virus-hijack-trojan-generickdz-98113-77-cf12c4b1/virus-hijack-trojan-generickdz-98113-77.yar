rule Virus_Hijack_Trojan_GenericKDZ_98113_77 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_77.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c52db3bd2cf123625648200ee5278f5c0afb83582fbd009f5bb9b1b23eb094f8"

  strings:
    $s1 = "features of the software will stop running.E1C" fullword ascii
    $s2 = "bsingle server or multiple servers, regardless of whether or not the individual is actively using the programs at any given time" ascii
    $s3 = "bsingle server or multiple servers, regardless of whether or not the individual is actively using the programs at any given time" ascii
    $s4 = "}Ragreements or representations, written or oral, " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}