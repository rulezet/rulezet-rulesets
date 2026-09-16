rule _20160921_8a4a5c81c02126f78061e6b947b8f9bc_20160921_c6bbdc353079_3076 {
  meta:
    description = "datamaliciousorder - from files 20160921_8a4a5c81c02126f78061e6b947b8f9bc.js, 20160921_c6bbdc353079233dc4959e9d0d85bc2d.js, 20160921_f7fa978ba93ca4504da33fc02cbf7f53.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3543e3d5dddde5efe5675e5ec649f9614fc6d9e81a903f893466af300e1dc64b"
    hash2       = "6fbb4e2c3fc90d9c1f39093c60f9a0294627c14ec844d16cb99b4f2b5fc1c158"
    hash3       = "8c8d20603b0870465254e9f226f52f020b5b1d986c61571e7a3097b32ea728e0"

  strings:
    $s1 = "u\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s2 = "){return \"Mw\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"DWe\";})(" ascii
    $s3 = "rn \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"LGo\";})(),(" ascii
    $s4 = "ion fuck(){return \"Xg\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return " ascii
    $s5 = "fuck(){return \"Ve\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Pc" ascii
    $s6 = "function fuck(){return \"KVh\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){r" ascii
    $s7 = "(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"OQr\";})(),(function fuck()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}