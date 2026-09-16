rule _Virus_Hijack_Gen_Trojan_ShellObject_uGZ_ayM4QWg_34_2_Virus_Infe_8 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.uGZ@ayM4QWg_34_2.vir, Virus.Infector_Win32.Expiro.Gen.7_83.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a28aca1e14dd45c40c95cb0f15fc574313eb1ca464517d5b014f5996d4a7e741"
    hash2       = "288a991ccc3f45150cda5a671461454ca4a9c32c4fff0ad6d6d395838677c9a7"

  strings:
    $s1 = "Microsoft Visual C++ 2010  x86 Redistributable Setup" fullword wide
    $s2 = "Microsoft Visual C++ 2010  x86 Redistributable" fullword wide
    $s3 = "(#DiGs" fullword ascii
    $s4 = "{,WHiz" fullword ascii
    $s5 = "ADaT;N" fullword ascii
    $s6 = "puRR%G" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}