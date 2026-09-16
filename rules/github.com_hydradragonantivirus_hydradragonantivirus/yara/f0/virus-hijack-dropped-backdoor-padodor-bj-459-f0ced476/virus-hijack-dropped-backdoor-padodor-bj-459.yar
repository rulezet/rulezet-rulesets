rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_459 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_459.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db6b709a9cc8f2789d2028d01bb91d653b36c77885ca3215e4cacc6c0142f003"

  strings:
    $s1 = "Jprevent either party from disclosing the terms o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}