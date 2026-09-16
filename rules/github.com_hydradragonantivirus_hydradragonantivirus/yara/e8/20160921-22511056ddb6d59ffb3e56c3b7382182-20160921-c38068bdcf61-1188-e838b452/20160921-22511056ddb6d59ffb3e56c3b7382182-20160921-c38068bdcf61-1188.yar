rule _20160921_22511056ddb6d59ffb3e56c3b7382182_20160921_c38068bdcf61_1188 {
  meta:
    description = "datamaliciousorder - from files 20160921_22511056ddb6d59ffb3e56c3b7382182.js, 20160921_c38068bdcf6149dc68d38cbcccfe991f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a5f7b2bfdf24defc0d363114441d0c0a0452fd599bf21d359b1b5f068dfc567"
    hash2       = "d59dd40562ac50a453dbb7054114c62cfd7c63d24b81c776b35af40fb9aa3480"

  strings:
    $s1  = "})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Xw\";})(),(function fuck" ascii
    $s2  = "nction fuck(){return \"Xw\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){retu" ascii
    $s3  = " fuck(){return \"We\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IP" ascii
    $s4  = "fuck(){return \"XHj\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IP" ascii
    $s5  = "),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Py\";})(),(function fuck(){" ascii
    $s6  = "turn \"Xw\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Xw\";})(),(f" ascii
    $s7  = "function fuck(){return \"XCr\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){ret" ascii
    $s8  = "ck(){return \"Ot\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\"" ascii
    $s9  = "ction fuck(){return \"Oh\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){retur" ascii
    $s10 = "(function fuck(){return \"Xw\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){re" ascii
    $s11 = "eturn \"Wo0\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s12 = "\"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xg\";})(),(functi" ascii
    $s13 = "rn \"DWe\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s14 = "function fuck(){return \"Zy\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s15 = "w\";})(),(function fuck(){return \"VMi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Xw\";})(),(function " ascii
    $s16 = "\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}