rule _20160921_1c739a510b202fd8658c1445b926e28b_20160921_acea633b7398_1675 {
  meta:
    description = "datamaliciousorder - from files 20160921_1c739a510b202fd8658c1445b926e28b.js, 20160921_acea633b73985995ce9764bf94db0972.js, 20160921_dd42e850834f3af27a08edf609a699b5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef5e44b6b8f05f9e4eadc507955ef770936acdd360f7dcfe6bb70a36427b04b7"
    hash2       = "dd77df78b3a755b016a27bbcac8fe7c015ab04472e2ca2d2d9aa476befb3148a"
    hash3       = "d7708087ab30a8d0d937f9d460512c05c37534c0d3c387bd3e1dd7fcb84fdc58"

  strings:
    $s1  = "function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){re" ascii
    $s2  = "on fuck(){return \"Sx\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s3  = "function fuck(){return \"Nm\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){retu" ascii
    $s4  = "urn \"Ve\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Pc\";})(),(fu" ascii
    $s5  = "\"CCb\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s6  = "n fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"" ascii
    $s7  = "urn \"XHj\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s8  = " \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Jh\";})(),(funct" ascii
    $s9  = "{return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"ADy\";})(" ascii
    $s10 = "{return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"ZVi\";}" ascii
    $s11 = "n \"XCr\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}