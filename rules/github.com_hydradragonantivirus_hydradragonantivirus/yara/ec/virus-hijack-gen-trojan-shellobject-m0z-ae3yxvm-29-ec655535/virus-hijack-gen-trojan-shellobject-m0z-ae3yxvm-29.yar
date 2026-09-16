rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_ae3yXvm_29 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_29.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef1647135daa6ba6c97e580bc922eeba4ba50b29e86f00dd79e58a026a1f018a"

  strings:
    $s1 = ">4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}