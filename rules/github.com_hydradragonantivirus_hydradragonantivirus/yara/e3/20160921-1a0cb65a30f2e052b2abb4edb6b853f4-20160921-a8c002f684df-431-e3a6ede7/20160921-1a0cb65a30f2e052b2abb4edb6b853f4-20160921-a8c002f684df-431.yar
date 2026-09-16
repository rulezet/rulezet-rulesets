rule _20160921_1a0cb65a30f2e052b2abb4edb6b853f4_20160921_a8c002f684df_431 {
  meta:
    description = "datamaliciousorder - from files 20160921_1a0cb65a30f2e052b2abb4edb6b853f4.js, 20160921_a8c002f684df9aec957f2a082ed80d84.js, 20160921_ba57fd323c757d83bd9bb08cdba3b4a4.js, 20160921_efc4e68608b4bd36f7e16eb4722b21c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb576c42df90a554f241d4a5ba0dee1dfcb9caf661cf46a2800b743aa592e644"
    hash2       = "9db5f5694048d441a47fe4382700213cc288d4fba152eec7b99fdd310a50ef7d"
    hash3       = "119b312aafd59cd12991442685e391e8850e3417b81d4aa79ae8e5c89a75f170"
    hash4       = "fe50eec4105613d48ac273c2d63a5b952098f339f7f06871b77053c43642dba7"

  strings:
    $s1  = "){return \"IKv\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";}" ascii
    $s2  = "uck(){return \"TTs\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Ve" ascii
    $s3  = "XHj\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(),(functi" ascii
    $s4  = "Bg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Ve\";})(),(function" ascii
    $s5  = "fuck(){return \"TTs\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Vb" ascii
    $s6  = "(){return \"UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"IOs\"" ascii
    $s7  = "nction fuck(){return \"Qh\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){retu" ascii
    $s8  = "k(){return \"Yb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";" ascii
    $s9  = " \"RAi\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s10 = "){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"USf\";}" ascii
    $s11 = "n fuck(){return \"Jo\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"I" ascii
    $s12 = "turn \"Nm\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})()," ascii
    $s13 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"" ascii
    $s14 = "){return \"GJx\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";" ascii
    $s15 = "ction fuck(){return \"TTs\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){retur" ascii
    $s16 = "l\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(functio" ascii
    $s17 = "ion fuck(){return \"CTm\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return " ascii
    $s18 = "eturn \"Nm\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()" ascii
    $s19 = "eturn \"ZVi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Hs\";})()" ascii
    $s20 = "\"OQr\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Ar\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}