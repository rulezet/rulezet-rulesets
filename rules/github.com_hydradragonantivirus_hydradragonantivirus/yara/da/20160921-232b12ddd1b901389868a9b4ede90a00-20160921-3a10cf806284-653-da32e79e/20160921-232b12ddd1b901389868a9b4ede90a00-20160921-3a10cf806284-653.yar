rule _20160921_232b12ddd1b901389868a9b4ede90a00_20160921_3a10cf806284_653 {
  meta:
    description = "datamaliciousorder - from files 20160921_232b12ddd1b901389868a9b4ede90a00.js, 20160921_3a10cf80628434d9e46f20272ebff11d.js, 20160921_a10895ba237c1e6f37301bc7a7a20160.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6982702aaaeaeac05c8666dd848834fd26e9eba567a0d41d04253252c120cdfe"
    hash2       = "c217c4eb7bba8a6770bdd6609635a67fc8772b37668310875b4f4f1ff0b472c2"
    hash3       = "a07dda373b4221628323bb92f53033ef3290be02ec657056fbf01d7d1efe96d7"

  strings:
    $s1  = "on fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"" ascii
    $s2  = "uck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"XCr" ascii
    $s3  = "ion fuck(){return \"USf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return " ascii
    $s4  = "Xf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"DWe\";})(),(functio" ascii
    $s5  = ")(),(function fuck(){return \"We\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"RAi\";})(),(function fuck" ascii
    $s6  = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return " ascii
    $s7  = "ck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"UXf" ascii
    $s8  = "\"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Sx\";})(),(funct" ascii
    $s9  = "t\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(functio" ascii
    $s10 = "n \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s11 = "\"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"PDf\";})(),(func" ascii
    $s12 = "nction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){retu" ascii
    $s13 = "k(){return \"IPu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu\"" ascii
    $s14 = "Bg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"FJs\";})(),(functi" ascii
    $s15 = "\"AUx\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(func" ascii
    $s16 = "uck(){return \"To\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg" ascii
    $s17 = "k(){return \"IPu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"USf\"" ascii
    $s18 = "urn \"XHj\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"GNm\";})(),(f" ascii
    $s19 = "turn \"Xw\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Xw\";})(),(f" ascii
    $s20 = "fuck(){return \"Xw\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Xw" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}