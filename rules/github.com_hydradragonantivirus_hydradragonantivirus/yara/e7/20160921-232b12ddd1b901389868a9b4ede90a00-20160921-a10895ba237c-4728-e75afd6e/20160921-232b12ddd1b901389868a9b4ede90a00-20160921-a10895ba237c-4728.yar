rule _20160921_232b12ddd1b901389868a9b4ede90a00_20160921_a10895ba237c_4728 {
  meta:
    description = "datamaliciousorder - from files 20160921_232b12ddd1b901389868a9b4ede90a00.js, 20160921_a10895ba237c1e6f37301bc7a7a20160.js, 20160921_c4701eeb8c1954cdca7ebff879af825b.js, 20160921_cbf1d4fc4e95f977458908fce0f55adb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6982702aaaeaeac05c8666dd848834fd26e9eba567a0d41d04253252c120cdfe"
    hash2       = "a07dda373b4221628323bb92f53033ef3290be02ec657056fbf01d7d1efe96d7"
    hash3       = "434597ea9990301d4bb62f8905b136fc4a13b61d61fa5eeef5efdc7757f1f1bc"
    hash4       = "de5ba60f48e78004cd5ec7a5ae764a46be1381f19aa87a961c3937fd05a1e2ec"

  strings:
    $s1 = "function fuck(){return \"Hs\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){re" ascii
    $s2 = "\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"ZLd\";})(),(function" ascii
    $s3 = "){return \"DRx\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"DRx\";}" ascii
    $s4 = "ction fuck(){return \"XCr\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii
    $s5 = "DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"GNm\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}