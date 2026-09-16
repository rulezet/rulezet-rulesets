rule _20160921_627f79d589bde52c443bc2d40f887ced_20160921_c779962dc8b3_134 {
  meta:
    description = "datamaliciousorder - from files 20160921_627f79d589bde52c443bc2d40f887ced.js, 20160921_c779962dc8b38bbb280b695e631131fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f23a9d984b71a422ca30ec7f94f4a4cb0a2303699dc80edbced4a4c608e370e4"
    hash2       = "cf3f9e3180d8fa16719dbea90d762850a1742512c7be6bc42325dc9e094add30"

  strings:
    $s1  = "urn \"TTs\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Hs\";})(),(f" ascii
    $s2  = "\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Oh\";})(),(function f" ascii
    $s3  = "USf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"NKq\";})(),(functio" ascii
    $s4  = "ction fuck(){return \"ZLd\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){retur" ascii
    $s5  = " \"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"Jo\";})(),(func" ascii
    $s6  = "eturn \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})()" ascii
    $s7  = "(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Sx\";})(),(function fuck()" ascii
    $s8  = "ck(){return \"OQr\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"OQr" ascii
    $s9  = "n \"Xw\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Xw\";})(),(fun" ascii
    $s10 = "){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"We\";})" ascii
    $s11 = ";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XHj\";})(),(function fu" ascii
    $s12 = "),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){" ascii
    $s13 = "i\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function" ascii
    $s14 = "})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Ve\";})(),(function fuck" ascii
    $s15 = "u\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Sx\";})(),(function f" ascii
    $s16 = "\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Mw\";})(),(function f" ascii
    $s17 = "\"DAa\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Wo\";})(),(func" ascii
    $s18 = "tion fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return" ascii
    $s19 = "rn \"Xg\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"KVh\";})(),(f" ascii
    $s20 = "),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"GJx\";})(),(function fuck(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}