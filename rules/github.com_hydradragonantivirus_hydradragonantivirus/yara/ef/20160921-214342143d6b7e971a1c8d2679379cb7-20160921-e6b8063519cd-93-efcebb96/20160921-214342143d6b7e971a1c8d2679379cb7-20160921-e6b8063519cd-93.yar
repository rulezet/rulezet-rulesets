rule _20160921_214342143d6b7e971a1c8d2679379cb7_20160921_e6b8063519cd_93 {
  meta:
    description = "datamaliciousorder - from files 20160921_214342143d6b7e971a1c8d2679379cb7.js, 20160921_e6b8063519cd61bbba9375bf86215501.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8dcc208c118a95c2f88df14e844ed832ee1e06bdf992329e8a721bd7aaa936e8"
    hash2       = "70ad2f9c8f844d4c80b1d4ce0f71f62f74e64671ae11d2d3af8e6ec764993403"

  strings:
    $s1  = "e\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"USf\";})(),(function" ascii
    $s2  = " \"DRx\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s3  = "ck(){return \"USf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Jo\"" ascii
    $s4  = "ck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Fv" ascii
    $s5  = "u\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Cd\";})(),(function" ascii
    $s6  = ";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuc" ascii
    $s7  = "k(){return \"ADy\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";" ascii
    $s8  = "urn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Ar\";})(),(f" ascii
    $s9  = "(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"MIl\";})(),(function fuck" ascii
    $s10 = "fuck(){return \"Wo0\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"B" ascii
    $s11 = "tion fuck(){return \"AUx\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){retur" ascii
    $s12 = "(){return \"PDf\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";" ascii
    $s13 = " \"TTs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Hs\";})(),(funct" ascii
    $s14 = " \"Ar\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"MIl\";})(),(fun" ascii
    $s15 = "k(){return \"XHj\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg" ascii
    $s16 = "urn \"QTc\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})()," ascii
    $s17 = "urn \"Ot\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s18 = "tion fuck(){return \"CCb\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return " ascii
    $s19 = " \"Jo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";})(),(func" ascii
    $s20 = "tion fuck(){return \"Np\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}