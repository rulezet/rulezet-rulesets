rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aiZXqXc_11_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aiZXqXc_11_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "77525158fc61a08878ee96643ed0ec90b2802149074c62ebc71e32e916cd1990"

  strings:
    $s1  = "<p>Codeproject is nice place indeed:<br><br><b><u>http://www.codeproject.com/</u></b></p>" fullword ascii
    $s2  = "Intel(R) processors with Intel(R) AVX-1.X instructions support" fullword ascii
    $s3  = "Intel(R) processors with Intel(R) AVX instructions support" fullword ascii
    $s4  = "<p>Hello my name is <b>Ernest Laurentin</b>.<br>Thanks for using WTL version this HTML ListView</p>" fullword ascii
    $s5  = "&New Account (Alt + N)" fullword wide
    $s6  = "&Delete Account (Alt + D)" fullword wide
    $s7  = "Enable &synchronize system for this account" fullword wide
    $s8  = "(c) 2015 Company  Kaspersky Laboratory" fullword wide
    $s9  = "Identif&y missing local files on upload" fullword wide
    $s10 = "String != NULL && *String != NULL" fullword wide
    $s11 = "MARBLES" fullword ascii
    $s12 = "Syncsession Aggregate Centrim Catches Cookies Irowsetresynch" fullword wide
    $s13 = "<p>Original code from: <b>Manoj Subberwal</b><br>Copyright (c) 2006</p>" fullword ascii
    $s14 = "Edit Reference's Values" fullword ascii
    $s15 = "0Add, edit or delete values to selected reference" fullword ascii
    $s16 = "Size != NULL" fullword wide
    $s17 = "&Utilizza Directory Opus per gestire gli archivi ZIP" fullword wide
    $s18 = "Vuoi che Directory Opus venga usato per gestire gli archivi ZIP?" fullword wide
    $s19 = "&Panel de Util:" fullword wide
    $s20 = "&Barra de Estado:" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}