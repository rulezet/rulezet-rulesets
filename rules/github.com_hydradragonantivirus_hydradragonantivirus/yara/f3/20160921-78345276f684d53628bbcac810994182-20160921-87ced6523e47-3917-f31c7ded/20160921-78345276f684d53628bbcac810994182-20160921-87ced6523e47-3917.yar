rule _20160921_78345276f684d53628bbcac810994182_20160921_87ced6523e47_3917 {
  meta:
    description = "datamaliciousorder - from files 20160921_78345276f684d53628bbcac810994182.js, 20160921_87ced6523e47b3b752b2353107bc989a.js, 20160921_945a46518061bd8e157aed251e0ffa9e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17b203684b4f2284de883c81e8fef63ea03c36bd0599ccb85d3175be35d9ac6d"
    hash2       = "46c521beb23d37cfa4d60cfcab38c941734971fe3102123b7e4c2813544d39b6"
    hash3       = "cc3d236edb3b45a767b438fa21243a07176d6f5def724e03e45aca76b3127054"

  strings:
    $s1 = "fuck(){return \"Nm\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"IPu" ascii
    $s2 = "uck(){return \"USf\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg" ascii
    $s3 = "return \"We\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"NKq\";})()" ascii
    $s4 = "\"Dc\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Yk\";})(),(funct" ascii
    $s5 = "fuck(){return \"Jh\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Et" ascii
    $s6 = ",(function fuck(){return \"Tv\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}