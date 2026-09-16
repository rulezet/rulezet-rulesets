rule Virus_Hijack_Trojan_GenericKDZ_105921_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105921_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "830b1d493266e8a6fbda79f7ad3eea93f25565ac03fa266f9637435bd55a6ec2"

  strings:
    $s1 = "e@2013 software. For your convenience, we" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}