rule Virus_Hijack_Gen_Trojan_ShellObject_C8Z_aG4fkNb_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.C8Z@aG4fkNb_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "632500a0186c832d239be4efb2b097b59f94cc5c4a7f89c0efeeaf7327e6fefa"

  strings:
    $s1 = ".$[KASA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}