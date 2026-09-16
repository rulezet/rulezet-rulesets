rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_161_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_161_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01d120aa60cf531112e0c6efe7191b4d9e9fb49097e709a4f277810bceda8d60"

  strings:
    $s1 = "7-Zip 19.00 (x64) is uninstalled" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}