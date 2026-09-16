rule Virus_Hijack_Gen_Trojan_ShellObject_oyZ_aeWgNZc_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.oyZ@aeWgNZc_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cabf9c316a1a4cf8ff96df9c4e75c4509b1e246fb36fa77e7ad11428c4cb0fc2"

  strings:
    $s1 = "[+]Got the address to write 0x%x" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}