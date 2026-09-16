rule Virus_Hijack_Backdoor_Hangup_B_279_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_279_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b99b1dcfd70ef41696eb6b6620e6777b4f75088c9604151f7cc8653122a344b"

  strings:
    $s1 = "reg delete \"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Active Setup\\Installed Components\\" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}