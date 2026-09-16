rule _20160921_052f92106046138b3c82e05878edd3a8_20160921_0d4a04b6f479_2217 {
  meta:
    description = "datamaliciousorder - from files 20160921_052f92106046138b3c82e05878edd3a8.js, 20160921_0d4a04b6f4795f89c068cce75e132259.js, 20160921_814859e3f9dab39a18edf940d1dd5650.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4812ea00b657b288e9ad51c72fcf466179e82a552fa3278fa9a896cc053c9fdc"
    hash2       = "e80f63f8ef5a9b52f119cc58d120fd7d74784d15d23ddc339948cb92383c800c"
    hash3       = "c61c4f66b5cb5b5fa606db7d7b914cbb3fe4d8f1b8ae72ca6b16b707c575cfb0"

  strings:
    $s1 = "Jh\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(functio" ascii
    $s2 = " \"GJx\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"ADy\";})(),(fu" ascii
    $s3 = " \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Jh\";})(),(func" ascii
    $s4 = "n \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"MUs\";})(),(f" ascii
    $s5 = "(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"NKq\";})(),(function fuck(" ascii
    $s6 = "ck(){return \"Jh\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"LGo" ascii
    $s7 = "nction fuck(){return \"MBg\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){retu" ascii
    $s8 = "),(function fuck(){return \"Jh\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}