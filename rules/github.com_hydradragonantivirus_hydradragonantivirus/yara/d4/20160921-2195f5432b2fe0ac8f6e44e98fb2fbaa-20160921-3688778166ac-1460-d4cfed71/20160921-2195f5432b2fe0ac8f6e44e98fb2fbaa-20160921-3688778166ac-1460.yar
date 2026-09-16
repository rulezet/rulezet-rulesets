rule _20160921_2195f5432b2fe0ac8f6e44e98fb2fbaa_20160921_3688778166ac_1460 {
  meta:
    description = "datamaliciousorder - from files 20160921_2195f5432b2fe0ac8f6e44e98fb2fbaa.js, 20160921_3688778166acb8f4f21b3c1d67ada442.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8753bd153b88da9a4351b5d6a0111d7af66a0f18e8b8a42beee11ad2916dc183"
    hash2       = "03559b6095f398f17a62ec1f50c0a70c4b4074a67f6b8e3a51dfe026b238b085"

  strings:
    $s1  = "unction fuck(){return \"Dc\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s2  = "ADy\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Wo0\";})(),(funct" ascii
    $s3  = "eturn \"DRx\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"ADy\";})()" ascii
    $s4  = "{return \"Xg\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Vf\";})(" ascii
    $s5  = "(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"FJs\";})(),(function fuck" ascii
    $s6  = "ion fuck(){return \"Wo\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return " ascii
    $s7  = "urn \"Vf\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"DWe\";})(),(" ascii
    $s8  = "tion fuck(){return \"XCr\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return " ascii
    $s9  = "Rx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Ot\";})(),(function" ascii
    $s10 = " fuck(){return \"Ot\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"OP" ascii
    $s11 = "n \"UOe\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Jh\";})(),(fu" ascii
    $s12 = ",(function fuck(){return \"Yk\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){r" ascii
    $s13 = "urn \"LGo\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"MUs\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}