rule _20160921_1d5a5ba6420732e8f626755a81334ad4_20160921_5143fd2835d0_679 {
  meta:
    description = "datamaliciousorder - from files 20160921_1d5a5ba6420732e8f626755a81334ad4.js, 20160921_5143fd2835d058f3854ef7b166166de4.js, 20160921_a84d89efd5400c906c1132a56b0ef679.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47a1fbd3f8785b259468283f9d6611b34da6b0170d66a933ade09c56548f89b4"
    hash2       = "0824c6197846b6efc3bea2626d4bc5983302ec11dd40189770e6572811d3d42c"
    hash3       = "f3cfecdabdf17d9af410d0fee7ec88844bc361668aca1a114832bd3e515d3456"

  strings:
    $s1  = "We\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(functio" ascii
    $s2  = "){return \"TTs\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"UOe\";}" ascii
    $s3  = "rn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Mw\";})(),(fu" ascii
    $s4  = "GNm\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"XFd\";})(),(funct" ascii
    $s5  = "urn \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(f" ascii
    $s6  = " fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"US" ascii
    $s7  = ")(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Hs\";})(),(function fuck" ascii
    $s8  = "uck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Ar" ascii
    $s9  = "eturn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Ai\";})()," ascii
    $s10 = "eturn \"YQt\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s11 = "n fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"D" ascii
    $s12 = "k(){return \"Jo\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Vb\";}" ascii
    $s13 = "\"Ot\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Nm\";})(),(funct" ascii
    $s14 = ";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"MUs\";})(),(function fuc" ascii
    $s15 = "nction fuck(){return \"ZWu\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){retu" ascii
    $s16 = "n fuck(){return \"Zy\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"G" ascii
    $s17 = ";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Np\";})(),(function fuc" ascii
    $s18 = "IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"IPu\";})(),(functi" ascii
    $s19 = "ck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Mw" ascii
    $s20 = "ction fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}