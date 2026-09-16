rule Virus_Hijack_Gen_Trojan_ShellObject_f8Y_aiYvnz_6_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aiYvnz_6_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca1f65c66d543807fb277681b6bb3212adb7f103e631c18a3d0559054bf8cbc4"

  strings:
    $s1 = " -w, --wow64    access 64 bit registry view (ignored on 32 bit Windows)" fullword ascii
    $s2 = " -W, --wow32    access 32 bit registry view (ignored on 32 bit Windows)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}