rule Virus_Hijack_Gen_Trojan_ShellObject_IyZ_aCEmdoo_14_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.IyZ@aCEmdoo_14_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "57d562d60571cc37f0c36724a65b753c4e6c72460f7125a92cdb4275326fbb2d"

  strings:
    $s1 = "Payment plans.docx" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}