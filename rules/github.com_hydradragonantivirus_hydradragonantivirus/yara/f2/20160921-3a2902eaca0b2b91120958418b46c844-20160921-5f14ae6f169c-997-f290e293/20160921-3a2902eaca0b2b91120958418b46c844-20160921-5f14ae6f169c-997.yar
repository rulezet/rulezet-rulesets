rule _20160921_3a2902eaca0b2b91120958418b46c844_20160921_5f14ae6f169c_997 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a2902eaca0b2b91120958418b46c844.js, 20160921_5f14ae6f169c53d6d49523d1e13e4ab9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "063bab1922376d926db97bdcd4342c2e9b0f2ec98d9fad81c2a3f86537c82b07"
    hash2       = "270eb53363684986d2aef11b6b5bb4cd5c5cb316f626e41b627db2cf899b440e"

  strings:
    $s1  = "\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Cd\";})(),(function f" ascii
    $s2  = " \"Jo\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"USf\";})(),(fun" ascii
    $s3  = "eturn \"We\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"LGo\";})()," ascii
    $s4  = "rn \"Cd\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(f" ascii
    $s5  = "uck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"FJs" ascii
    $s6  = "ck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Vf\"" ascii
    $s7  = "eturn \"XHj\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"ZWu\";})(" ascii
    $s8  = "ion fuck(){return \"MIl\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s9  = ")(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ai\";})(),(function fuck(" ascii
    $s10 = "unction fuck(){return \"Dc\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Et\";})(),(function fuck(){retu" ascii
    $s11 = "){return \"MBg\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"DWe\";}" ascii
    $s12 = "(function fuck(){return \"TTs\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){re" ascii
    $s13 = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s14 = " fuck(){return \"Nm\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"M" ascii
    $s15 = "\"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"UOe\";})(),(fun" ascii
    $s16 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Za\";})(),(function fuck(){retur" ascii
    $s17 = "rn \"Nm\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s18 = "})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Qh\";})(),(function fuck" ascii
    $s19 = "AUx\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"XFd\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}