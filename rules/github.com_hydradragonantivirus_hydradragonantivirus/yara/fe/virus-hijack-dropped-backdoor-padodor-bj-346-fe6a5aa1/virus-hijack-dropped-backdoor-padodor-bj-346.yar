rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_346 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_346.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37f6b077d07dbef9a6b7c369dfb49527dc0a87eef550ba20d624cf910c21c970"

  strings:
    $s1 = "prevent either party from disclosing the terms o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}