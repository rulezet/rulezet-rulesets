rule _20160921_b6523fd99592b93c7a07e8a0e3a5eaf2_20160921_ba57fd323c75_912 {
  meta:
    description = "datamaliciousorder - from files 20160921_b6523fd99592b93c7a07e8a0e3a5eaf2.js, 20160921_ba57fd323c757d83bd9bb08cdba3b4a4.js, 20160921_efc4e68608b4bd36f7e16eb4722b21c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c7380d8ae5ab67e50f821f2074c7903d887706b91f0b0d3dcfedf5bfbd9a62e0"
    hash2       = "119b312aafd59cd12991442685e391e8850e3417b81d4aa79ae8e5c89a75f170"
    hash3       = "fe50eec4105613d48ac273c2d63a5b952098f339f7f06871b77053c43642dba7"

  strings:
    $s1  = "on fuck(){return \"Jo\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"I" ascii
    $s2  = "(){return \"UOe\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"GWo\"" ascii
    $s3  = "nction fuck(){return \"CCb\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){retu" ascii
    $s4  = "fuck(){return \"IPu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"MO" ascii
    $s5  = "eturn \"ZWu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"MOj\";})()" ascii
    $s6  = "fuck(){return \"TTs\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Za" ascii
    $s7  = "tion fuck(){return \"Ar\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return" ascii
    $s8  = "(){return \"CCb\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";" ascii
    $s9  = "ction fuck(){return \"XHj\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii
    $s10 = "o\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"NKq\";})(),(function" ascii
    $s11 = "r\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Za\";})(),(function" ascii
    $s12 = "b\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s13 = "),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){" ascii
    $s14 = "{return \"RAi\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})" ascii
    $s15 = "),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){r" ascii
    $s16 = "on fuck(){return \"Pc\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"C" ascii
    $s17 = "eturn \"UOe\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"MOj\";})()," ascii
    $s18 = "\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Xg\";})(),(function " ascii
    $s19 = "rn \"Fv\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(f" ascii
    $s20 = ";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"MOj\";})(),(function fuc" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}