rule Virus_Hijack_GenPack_Backdoor_Hangup_B_204 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_204.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f37c75101808b9319338b843223e5d094cf227de2e47e5361db1c32a7dcdf9b"

  strings:
    $s1 = "_Vof the software and a separate license for each copy. Content protected by digital rights management" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}