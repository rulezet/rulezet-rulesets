rule _20160921_0298568f245d937dde081d505d360a5e_20160921_18f3609106b0_265 {
  meta:
    description = "datamaliciousorder - from files 20160921_0298568f245d937dde081d505d360a5e.js, 20160921_18f3609106b0af59da0b1200fe14abc1.js, 20160921_21041f3360c455bf09d8b48dda6959f3.js, 20160921_e4c63c3b699efd2f5fe2739b016a938a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f31455e0194491e66143329dadae1760f33af4219844671541520909cf32d58"
    hash2       = "95fb9e6292746461417b0e539747d500c780ad17cb775a9db031f77eaa53a3e2"
    hash3       = "de559d9fde4fb08962605e84afb3f8e86d21c757f1189b673ed0648e3dd75cd0"
    hash4       = "9d5d6c2986818649619806d890aad49cda8d0da47fe67f38388e5441a53382a0"

  strings:
    $s1  = "rn \"LGo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NKq\";})(),(" ascii
    $s2  = "k(){return \"Cd\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";" ascii
    $s3  = "ck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"NKq\"" ascii
    $s4  = "turn \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"LGo\";})()," ascii
    $s5  = ")(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(function fuc" ascii
    $s6  = "ck(){return \"IKv\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"USf" ascii
    $s7  = "{return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"RAi\";}" ascii
    $s8  = "urn \"Yk\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s9  = "eturn \"GNm\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()" ascii
    $s10 = "(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"CCb\";})(),(function fuck" ascii
    $s11 = "ion fuck(){return \"DWe\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return " ascii
    $s12 = "uck(){return \"MBg\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ve" ascii
    $s13 = "){return \"IPu\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";}" ascii
    $s14 = "ion fuck(){return \"IKv\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return" ascii
    $s15 = "USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"USf\";})(),(funct" ascii
    $s16 = "on fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"" ascii
    $s17 = "(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Np\";" ascii
    $s18 = "n \"OQr\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"AUx\";})(),(fu" ascii
    $s19 = "return \"ADy\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(" ascii
    $s20 = "){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}