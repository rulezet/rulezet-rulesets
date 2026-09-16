rule Virus_Infector_Win32_Worm_LightMoon_A_mm_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Worm.LightMoon.A@mm_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f421c1a8dd24d90c2fc12bcf2d623f604e0dfc8c5cc40210c9ee70a9d45f6f32"

  strings:
    $s1 = "coxa(_pU" fullword ascii
    $s2 = "=F<Seed" fullword ascii
    $s3 = "r,nEMA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}