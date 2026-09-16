rule Virus_Hijack_Gen_Trojan_ShellObject_l8Z_aKTibuk_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.l8Z@aKTibuk_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "15060c4dda1b9fd2f58e2836aeba2a72493819e44a23033114b5b1ebee19a6f4"

  strings:
    $s1 = "pAtomTable != NULL" fullword ascii
    $s2 = "phFile != NULL" fullword ascii
    $s3 = "qwszOriginalAccessPath != NULL" fullword ascii
    $s4 = "3Z((HANDLE)(LONG_PTR)-1) != hFile" fullword ascii
    $s5 = "3Q9pBSIToSave != NULL" fullword ascii
    $s6 = "]m_bRecreateDisks == FALSE" fullword ascii
    $s7 = "L{o7Fm_pValuesFirst == NULL" fullword ascii
    $s8 = "m_pVolumeCat != NULL" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}