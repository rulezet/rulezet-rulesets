rule _20160921_1bb9bdcf05b8f8acd28d5286e804d5cc_20160921_4fa304d7c11d_1544 {
  meta:
    description = "datamaliciousorder - from files 20160921_1bb9bdcf05b8f8acd28d5286e804d5cc.js, 20160921_4fa304d7c11deb5fb9cd6514d5a983de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3937dec3a8d946e214facedccfe7f35e65dbd446a77d077a09996638d7524444"
    hash2       = "cef5a1e67f57d9f24065ff0145644e0185df6abc29113310c6782b30e0a9236b"

  strings:
    $s1  = "function fuck(){return \"MBg\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){ret" ascii
    $s2  = "(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Vb\";}" ascii
    $s3  = "\"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"SUi\";})(),(funct" ascii
    $s4  = "turn \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})()," ascii
    $s5  = "rn \"Np\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"CCb\";})(),(f" ascii
    $s6  = "\"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(fun" ascii
    $s7  = "Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Oh\";})(),(function" ascii
    $s8  = ",(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){r" ascii
    $s9  = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){retur" ascii
    $s10 = "return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"GWo\";})(" ascii
    $s11 = "ck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"USf" ascii
    $s12 = "return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}