rule Virus_Sysbot_GenPack_Generic_Dacic_Emdup_A_9CFA97CE {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_GenPack.Generic.Dacic.Emdup.A.9CFA97CE.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7da2272a91863fed4948ad9b22177a3a4935953feea65a716f3993b84d65c6d"

  strings:
    $s1 = "Java(TM) Platform SE Auto Updater 2 0" fullword wide
    $s2 = "Java(TM) Update Client Checker" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}