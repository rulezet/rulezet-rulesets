rule Trojan_Danger_Trojan_GenericKD_72853156_608_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_608_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "861e1b59eab27330931dc56594e071bf968ca133f1c44f1bf778d5b9f3a5f3c6"

  strings:
    $s1 = "PSNR NTP Host Company" fullword wide
    $s2 = "PSNR NTP Space Provider" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}