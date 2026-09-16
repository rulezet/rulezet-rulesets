import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_dGX_aulKiep_8_1_Virus_Hijac_202 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.dGX@aulKiep_8_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.dGX@aulKiep_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0787baa6cb8bf2197562cedc818c0f7bb783aa8b0a51178daf9a93f98138f36"
    hash2       = "6e4caea7b0ae4383dd5b4e71daa6b698f4c277ae1034908219b9dafe6e2298d9"

  strings:
    $s1  = "postally" fullword ascii
    $s2  = "Conscript" fullword ascii
    $s3  = "deformative" fullword ascii
    $s4  = "allayment" fullword ascii
    $s5  = "aerometer" fullword ascii
    $s6  = "Actinium" fullword ascii
    $s7  = "Nonthinking" fullword ascii
    $s8  = "Aqueously" fullword ascii
    $s9  = "Blindly" fullword ascii
    $s10 = "Buttonhole" fullword ascii
    $s11 = "dacoit" fullword ascii
    $s12 = "fouler" fullword wide
    $s13 = "abdicable" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "586b2a5d433dad050636d9e0a686ea39" and (8 of them)
    ) or (all of them)
}