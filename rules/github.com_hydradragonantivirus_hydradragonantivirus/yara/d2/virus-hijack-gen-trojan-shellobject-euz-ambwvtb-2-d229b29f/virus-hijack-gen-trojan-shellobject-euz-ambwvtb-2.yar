rule Virus_Hijack_Gen_Trojan_ShellObject_EuZ_amBwvTb_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.EuZ@amBwvTb_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7bc7a4c39ae7de8d6561514291132eafa9c58c68f34a62017eb49b934ddb296a"

  strings:
    $s1 = "process id %u" fullword ascii
    $s2 = "memory address : %x" fullword ascii
    $s3 = "d File Info>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}