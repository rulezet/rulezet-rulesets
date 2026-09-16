rule _20160921_01da6b0c1b5614c5877e0dd7b6be4036_20160921_17642c69cbfb_1760 {
  meta:
    description = "datamaliciousorder - from files 20160921_01da6b0c1b5614c5877e0dd7b6be4036.js, 20160921_17642c69cbfb276056f3695ae22dad4c.js, 20160921_5831ee10eea30ef3b8363cda03eba31a.js, 20160921_be8454f98b5a24b3ec56590bd13ee274.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5da941f7d098e0926acf7ad9efedc9f91495115fc83f288580eba79e44574693"
    hash2       = "4cdbf9fba4e3fec424cf182fd21fa3c400b0649ca09f140375a47df12248955c"
    hash3       = "2249c045e34389dbbb9e3554dc23ae5207cc7f4205df2feaede6b0df279995cb"
    hash4       = "984696d2831d222abf66218ad54b440a2fd79bd47a7f1493a197576207321839"

  strings:
    $s1  = "(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"YQt\";})(),(function fuck" ascii
    $s2  = " fuck(){return \"SUi\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"" ascii
    $s3  = "){return \"XCr\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";" ascii
    $s4  = "){return \"ZLd\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";" ascii
    $s5  = "n \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Nm\";})(),(func" ascii
    $s6  = "ion fuck(){return \"Np\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return " ascii
    $s7  = "k(){return \"QTc\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\"" ascii
    $s8  = "return \"ADy\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Mw\";})(" ascii
    $s9  = "x\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Sx\";})(),(function " ascii
    $s10 = "nction fuck(){return \"OQr\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}