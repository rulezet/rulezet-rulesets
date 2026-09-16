rule Virus_Sysbot_GenPack_Generic_Dacic_Emdup_A_34291B55_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_GenPack.Generic.Dacic.Emdup.A.34291B55_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "075d092b1ef95abb7e0f7f2cd4e957649b01518d0a221b864be1de29ab7db2d6"

  strings:
    $s1 = ";pISK*" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}