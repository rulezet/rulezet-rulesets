rule Virus_Hijack_Backdoor_Hangup_B_49_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_49_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc3d294886e92caa2eca8d14e764e2c1b5e2e0b1eae2d5d4863a28b48908a79a"

  strings:
    $s1 = "disclosure. Also, we each agree to disclose confidential information only to those employees or agents" fullword ascii
    $s2 = "r terms come with them." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}