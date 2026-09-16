rule Virus_Hijack_Gen_Trojan_ShellObject_ryZ_ayMBdto_6_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ryZ@ayMBdto_6_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31a065211f53048b3bab45dc544a8312293a84c0a3e6d6a9dc8a0be98b054478"

  strings:
    $s1 = "ft Visual Studio\\" fullword ascii
    $s2 = "Timer&" fullword ascii
    $s3 = "g#Conk" fullword ascii
    $s4 = "Copy@N" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}