rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aG5Bc5o_13_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_13_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "579747fcbd3c92620c07661e591ee3b64e524c222ff1fb95d634261f08cb2789"

  strings:
    $s1 = "?A0xcce04ccc.??__E?InitializedPerProcess@CurrentDomain@<CrtImplementationDetails>@@$$Q2W4State@Progress@2@A@@YMXXZ" fullword ascii
    $s2 = "11.0.61135.400 built by: RTMLDR" fullword wide
    $s3 = "?A0xcce04ccc.??__E?InitializedNative@CurrentDomain@<CrtImplementationDetails>@@$$Q2W4State@Progress@2@A@@YMXXZ" fullword ascii
    $s4 = "?A0xcce04ccc.??__E?InitializedPerAppDomain@CurrentDomain@<CrtImplementationDetails>@@$$Q2W4State@Progress@2@A@@YMXXZ" fullword ascii
    $s5 = "?A0xcce04ccc.??__E?InitializedVtables@CurrentDomain@<CrtImplementationDetails>@@$$Q2W4State@Progress@2@A@@YMXXZ" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}