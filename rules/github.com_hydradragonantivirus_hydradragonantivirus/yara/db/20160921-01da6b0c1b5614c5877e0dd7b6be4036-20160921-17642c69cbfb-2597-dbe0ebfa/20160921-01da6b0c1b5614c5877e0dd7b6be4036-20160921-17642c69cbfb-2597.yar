rule _20160921_01da6b0c1b5614c5877e0dd7b6be4036_20160921_17642c69cbfb_2597 {
  meta:
    description = "datamaliciousorder - from files 20160921_01da6b0c1b5614c5877e0dd7b6be4036.js, 20160921_17642c69cbfb276056f3695ae22dad4c.js, 20160921_d88b1be24c583b3513de141e173a825f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5da941f7d098e0926acf7ad9efedc9f91495115fc83f288580eba79e44574693"
    hash2       = "4cdbf9fba4e3fec424cf182fd21fa3c400b0649ca09f140375a47df12248955c"
    hash3       = "be789e0d16008ea27a540870c4b670071885fb31e3c8c6ebfb775def3b30a551"

  strings:
    $s1 = "function fuck(){return \"MIl\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){re" ascii
    $s2 = "ZLd\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"ADy\";})(),(functio" ascii
    $s3 = "){return \"DRx\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Np\";})" ascii
    $s4 = "})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"IPu\";})(),(function fu" ascii
    $s5 = "ion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return " ascii
    $s6 = "tion fuck(){return \"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return" ascii
    $s7 = "return \"To\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}