rule Virus_Hijack_Gen_Trojan_ShellObject_v4Z_aqH1LVc_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.v4Z@aqH1LVc_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1f23a727bc45b97b77241faa7350052e0369d72e8a358b8a862ee3d9bfc0f87"

  strings:
    $s1 = "J)must be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}