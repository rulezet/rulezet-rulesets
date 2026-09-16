rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aaajMem_12 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aaajMem_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "455a81f068b1a4d13e4231868692a728c1fff9604d5583523878d6b1f7106435"

  strings:
    $s1 = "pAut*\\z" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}