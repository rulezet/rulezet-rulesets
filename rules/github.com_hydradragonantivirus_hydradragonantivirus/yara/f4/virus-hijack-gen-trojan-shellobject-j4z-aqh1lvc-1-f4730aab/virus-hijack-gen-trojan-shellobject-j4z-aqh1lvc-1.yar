rule Virus_Hijack_Gen_Trojan_ShellObject_j4Z_aqH1LVc_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j4Z@aqH1LVc_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f80901b5ef7fc2e80af477565b4eab3f4b3e68af66de1e3e1ac759c9d39c715"

  strings:
    $s1 = "Amust be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}