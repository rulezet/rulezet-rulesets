rule _20160921_be8454f98b5a24b3ec56590bd13ee274_20160921_f575ae0885e7_786 {
  meta:
    description = "datamaliciousorder - from files 20160921_be8454f98b5a24b3ec56590bd13ee274.js, 20160921_f575ae0885e764a3ea3a621283d492e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "984696d2831d222abf66218ad54b440a2fd79bd47a7f1493a197576207321839"
    hash2       = "56a063ba0d781a52d612f976f937d59e64bb8200cf3c4b448f3cb3013733bdaf"

  strings:
    $s1  = "urn \"YQt\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(" ascii
    $s2  = "uck(){return \"AUx\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"CT" ascii
    $s3  = "){return \"XHj\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"IPu\";" ascii
    $s4  = "\"Jo\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(funct" ascii
    $s5  = "Fv\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"YAv\";})(),(functio" ascii
    $s6  = "x\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s7  = "){return \"Xg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Jo\";})" ascii
    $s8  = " fuck(){return \"Hs\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MB" ascii
    $s9  = "(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(" ascii
    $s10 = "ck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"QTc" ascii
    $s11 = "on fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return " ascii
    $s12 = "k(){return \"Ve\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Pc\";}" ascii
    $s13 = "rn \"Hs\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(f" ascii
    $s14 = " \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Et\";})(),(fun" ascii
    $s15 = "rn \"Dc\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IOs\";})(),(fu" ascii
    $s16 = "CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"DWe\";})(),(functi" ascii
    $s17 = "turn \"CTm\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Dc\";})()," ascii
    $s18 = "(function fuck(){return \"Pc\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){re" ascii
    $s19 = "(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"IPu\"" ascii
    $s20 = "nction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}