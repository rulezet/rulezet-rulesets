rule Virus_Hijack_Backdoor_Hangup_B_61 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_61.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "341c146e86ea11b06d2c5d88f85bbf6bfa0c18b85af62cd17c5f2d27c4ef110c"

  strings:
    $s1 = "&Trade Compliance web site which can be accessed at http://oracle.com/contracts. You agree that no data, information," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}