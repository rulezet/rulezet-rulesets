rule Trojan_Autorun_Win32_Neshta_A_8_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Win32.Neshta.A_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4240ce88d0e90e2203dadf544b2eaba86f62c8a378d89937f71270f526812100"

  strings:
    $s1 = "Nprogram and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viol" ascii
    $s2 = "Nprogram and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viol" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}