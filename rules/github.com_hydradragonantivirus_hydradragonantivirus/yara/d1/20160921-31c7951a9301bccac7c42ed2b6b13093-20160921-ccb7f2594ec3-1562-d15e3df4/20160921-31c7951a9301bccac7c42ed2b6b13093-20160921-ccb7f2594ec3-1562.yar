rule _20160921_31c7951a9301bccac7c42ed2b6b13093_20160921_ccb7f2594ec3_1562 {
  meta:
    description = "datamaliciousorder - from files 20160921_31c7951a9301bccac7c42ed2b6b13093.js, 20160921_ccb7f2594ec30d819d8973993796faf6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "170c53b6198c4ffe293d40953d3f705212182666ee02a10f7b562b4a16af7559"
    hash2       = "d05110dd6f0ccc6122f08dac231858be0e233eb3cfb596f5f571556d227ab3ef"

  strings:
    $s1  = "unction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){ret" ascii
    $s2  = "n \"Yk\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(fu" ascii
    $s3  = "){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IPu\";}" ascii
    $s4  = "IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Fv\";})(),(functi" ascii
    $s5  = "return \"Xg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"CCb\";})()" ascii
    $s6  = "})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Jo\";})(),(function fuc" ascii
    $s7  = "function fuck(){return \"Pc\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){retu" ascii
    $s8  = "return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Jg\";})(" ascii
    $s9  = " fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"L" ascii
    $s10 = "turn \"QTc\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})()" ascii
    $s11 = "k\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(function" ascii
    $s12 = "\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"YAv\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}