rule _20160921_01da6b0c1b5614c5877e0dd7b6be4036_20160921_17642c69cbfb_4127 {
  meta:
    description = "datamaliciousorder - from files 20160921_01da6b0c1b5614c5877e0dd7b6be4036.js, 20160921_17642c69cbfb276056f3695ae22dad4c.js, 20160921_acea633b73985995ce9764bf94db0972.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5da941f7d098e0926acf7ad9efedc9f91495115fc83f288580eba79e44574693"
    hash2       = "4cdbf9fba4e3fec424cf182fd21fa3c400b0649ca09f140375a47df12248955c"
    hash3       = "dd77df78b3a755b016a27bbcac8fe7c015ab04472e2ca2d2d9aa476befb3148a"

  strings:
    $s1 = "ck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Wo0" ascii
    $s2 = "\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"ADy\";})(),(function" ascii
    $s3 = "(){return \"YQt\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";" ascii
    $s4 = "){return \"DWe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"IKv\";" ascii
    $s5 = "unction fuck(){return \"GNm\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}