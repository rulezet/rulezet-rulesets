rule _20160921_3a10cf80628434d9e46f20272ebff11d_20160921_4d79e96b422e_1197 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a10cf80628434d9e46f20272ebff11d.js, 20160921_4d79e96b422e6679059a17d9524e032c.js, 20160921_694d4629e99fd1d23d60bc73e0e28e30.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c217c4eb7bba8a6770bdd6609635a67fc8772b37668310875b4f4f1ff0b472c2"
    hash2       = "d5794a16a28dba8e89768fa9195da33a7e28c3da5fc73a7789e7c04395f23f06"
    hash3       = "01147c2f2f43df58f5a1b60481a04add7d73eba030abaeed3f9dedb1fd3574e4"

  strings:
    $s1  = "k(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"XHj\"" ascii
    $s2  = "YAv\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(functi" ascii
    $s3  = "\"XCr\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Xw\";})(),(func" ascii
    $s4  = "rn \"Xw\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Qh\";})(),(fu" ascii
    $s5  = "uck(){return \"To\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx" ascii
    $s6  = "\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function " ascii
    $s7  = "(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Xw\";}" ascii
    $s8  = "turn \"Ot\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"ZWu\";})()," ascii
    $s9  = "\"Xw\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"XCr\";})(),(func" ascii
    $s10 = "ck(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"DAa" ascii
    $s11 = "eturn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Sx\";})(),(" ascii
    $s12 = "{return \"XHj\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s13 = "nction fuck(){return \"YQt\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){retu" ascii
    $s14 = " fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"A" ascii
    $s15 = "{return \"VMi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Xw\";})()" ascii
    $s16 = "unction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}