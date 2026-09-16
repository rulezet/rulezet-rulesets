rule Virus_Hijack_Gen_Trojan_ShellObject_EuZ_amBwvTb_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.EuZ@amBwvTb_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "75bcf3a8bd7be1d578751b740f6d80e7713b97aac02ba47d8d2701b5ca44734e"

  strings:
    $s1 = "process id %u" fullword ascii
    $s2 = "memory address : %x" fullword ascii
    $s3 = "d File Info>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}