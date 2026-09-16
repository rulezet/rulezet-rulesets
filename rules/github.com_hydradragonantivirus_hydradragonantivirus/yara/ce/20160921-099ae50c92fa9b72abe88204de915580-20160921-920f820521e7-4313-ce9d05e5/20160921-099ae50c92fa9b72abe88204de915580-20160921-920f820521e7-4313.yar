rule _20160921_099ae50c92fa9b72abe88204de915580_20160921_920f820521e7_4313 {
  meta:
    description = "datamaliciousorder - from files 20160921_099ae50c92fa9b72abe88204de915580.js, 20160921_920f820521e7af7d81b11e9545080390.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "344e6822e369c3beb064ffee655d0ce0db901d1bada577cd8f338fc2aec06cb8"
    hash2       = "c4a6a94fe43f214f35574405d899a6d61259c2b1135c1ecf399630de11c6dea3"

  strings:
    $s1 = "uck(){return \"UOe\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IR" ascii
    $s2 = "(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(function fuck(" ascii
    $s3 = "tion fuck(){return \"Fv\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return " ascii
    $s4 = " \"Mw\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"ZWu\";})(),(fun" ascii
    $s5 = "})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"DRx\";})(),(function fuc" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}