rule Virus_Hijack_GenPack_Backdoor_Hangup_B_75 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_75.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2cff529e279623b91aecc8aa3c9274ab90884303d61dd767ff73a3e8fd647fbf"

  strings:
    $s1 = "Sand hardware systems to the applications programs and (c) building extensions to applications programs. You shall not" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}