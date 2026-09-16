rule Virus_Hijack_Dump_Generic_Dacic_DED21A61_A_CD7E6D9F {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dump.Generic.Dacic.DED21A61.A.CD7E6D9F.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9def24fd1ac0915b89b8199e688649c0f1d4c6c5cf742d37e924b9294499ac40"

  strings:
    $s1 = " Leviathan 2008" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}