rule Virus_Hijack_GenPack_Backdoor_Hangup_B_363 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_363.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "431b5daefcd9e44823e28b097e4cc1e3f00829ffff3a7f6966949f828cd17166"

  strings:
    $s1 = "HTrade Compliance web site which can be accessed at http://oracle.com/contracts. You agree that no data, information," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}