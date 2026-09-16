rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_177 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_177.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b46bb53076caa2c09695479796962ba332be8b38615d5def7c044d40ef0c664"

  strings:
    $s1 = "heme*em" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}