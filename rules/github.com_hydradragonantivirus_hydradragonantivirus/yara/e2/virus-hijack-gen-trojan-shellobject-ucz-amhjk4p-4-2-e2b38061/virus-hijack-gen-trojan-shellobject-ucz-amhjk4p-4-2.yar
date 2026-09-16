rule Virus_Hijack_Gen_Trojan_ShellObject_uCZ_amHJK4p_4_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.uCZ@amHJK4p_4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa6ddad6fe17cb73af3065c9abcfa11d84bdf311e796105643bad7016bb60220"

  strings:
    $s1 = "Start Enjoy!" fullword ascii
    $s2 = "Windows Server Longhorn" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}