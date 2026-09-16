rule Virus_Infector_Generic_Dacic_F7D02F69_A_AA885641 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Generic.Dacic.F7D02F69.A.AA885641.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d4ffed5ac9872a51191c657b6a3cb4f5770151f5dfa689c83cd1591773cacaaa"

  strings:
    $s1 = "FILE FOLDER*" fullword ascii
    $s2 = "?sOMA%#R60" fullword ascii
    $s3 = "@Clean" fullword ascii
    $s4 = "5t Visual Audio\\1C'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}