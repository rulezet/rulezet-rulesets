rule Virus_Infector_Win32_Expiro_Gen_7_144 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_144.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2117dd3e75c8edc53c8e130759b1209c40101da9f1e3738eef3fe798e3f28fdf"

  strings:
    $s1  = "Program Files(64)\\Microsoft Visual Studio 9.0\\Vc7\\WinSXS\\AMD64 catalogs\\Microsoft.VC90.OpenMP.cat" fullword ascii
    $s2  = "Program Files(64)\\Microsoft Visual Studio 9.0\\Vc7\\WinSXS\\AMD64 catalogs\\policy.9.00.Microsoft.VC90.MFCLOC.cat" fullword ascii
    $s3  = "Program Files(64)\\Microsoft Visual Studio 9.0\\Vc7\\WinSXS\\AMD64 catalogs\\policy.9.00.Microsoft.VC90.DebugOpenMP.cat" fullword ascii
    $s4  = "Program Files(64)\\Microsoft Visual Studio 9.0\\Vc7\\WinSXS\\AMD64 catalogs\\policy.9.00.Microsoft.VC90.ATL.cat" fullword ascii
    $s5  = "Program Files(64)\\Microsoft Visual Studio 9.0\\Vc7\\WinSXS\\AMD64 catalogs\\policy.9.00.Microsoft.VC90.DebugCRT.cat" fullword ascii
    $s6  = "Program Files(64)\\Microsoft Visual Studio 9.0\\Vc7\\WinSXS\\AMD64 catalogs\\policy.9.00.Microsoft.VC90.MFC.cat" fullword ascii
    $s7  = "Program Files(64)\\Microsoft Visual Studio 9.0\\Vc7\\WinSXS\\AMD64 catalogs\\Microsoft.VC90.CRT.cat" fullword ascii
    $s8  = "Program Files(64)\\Microsoft Visual Studio 9.0\\Vc7\\WinSXS\\AMD64 catalogs\\Microsoft.VC90.MFCLOC.cat" fullword ascii
    $s9  = "Program Files(64)\\Microsoft Visual Studio 9.0\\Vc7\\WinSXS\\AMD64 catalogs\\Microsoft.VC90.DebugCRT.cat" fullword ascii
    $s10 = "Program Files(64)\\Microsoft Visual Studio 9.0\\Vc7\\WinSXS\\AMD64 catalogs\\policy.9.00.Microsoft.VC90.OpenMP.cat" fullword ascii
    $s11 = "Program Files(64)\\Microsoft Visual Studio 9.0\\Vc7\\WinSXS\\AMD64 catalogs\\Microsoft.VC90.DebugOpenMP.cat" fullword ascii
    $s12 = "Program Files(64)\\Microsoft Visual Studio 9.0\\Vc7\\WinSXS\\AMD64 catalogs\\Microsoft.VC90.MFC.cat" fullword ascii
    $s13 = "Program Files(64)\\Microsoft Visual Studio 9.0\\Vc7\\WinSXS\\AMD64 catalogs\\Microsoft.VC90.ATL.cat" fullword ascii
    $s14 = "Program Files(64)\\Microsoft Visual Studio 9.0\\Vc7\\WinSXS\\AMD64 catalogs\\policy.9.00.Microsoft.VC90.CRT.cat" fullword ascii
    $s15 = "Program Files(64)\\Microsoft Visual Studio 9.0\\Vc7\\WinSXS\\AMD64 catalogs\\Microsoft.VC90.DebugMFC.cat" fullword ascii
    $s16 = "Program Files(64)\\Microsoft Visual Studio 9.0\\Vc7\\WinSXS\\AMD64 catalogs\\policy.9.00.Microsoft.VC90.DebugMFC.cat" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}