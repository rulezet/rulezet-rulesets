rule _20160921_105b4651b7160ca47c8bc86d4da31c43_20160921_64fd82bf037f_4392 {
  meta:
    description = "datamaliciousorder - from files 20160921_105b4651b7160ca47c8bc86d4da31c43.js, 20160921_64fd82bf037f1ee6b74269456349f2e6.js, 20160921_87ced6523e47b3b752b2353107bc989a.js, 20160921_945a46518061bd8e157aed251e0ffa9e.js, 20160921_f926399cbb634492c58e195c86a0bbde.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e64d089e7076541ade19a5701fb8571545dde4a6c002b31df5fef02095005f7"
    hash2       = "ba779a9cd5d48159c0b701ec2bc1832d098c0d5cf1f3a9429684810372bfa1b2"
    hash3       = "46c521beb23d37cfa4d60cfcab38c941734971fe3102123b7e4c2813544d39b6"
    hash4       = "cc3d236edb3b45a767b438fa21243a07176d6f5def724e03e45aca76b3127054"
    hash5       = "15b29ae0204a4b512f15931b197f4e0ddaad99fc24c68356f1631bedc62dcac6"

  strings:
    $s1 = "fuck(){return \"ADy\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"M" ascii
    $s2 = "n \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"UOe\";})(),(f" ascii
    $s3 = "),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck()" ascii
    $s4 = "uck(){return \"IKv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"UO" ascii
    $s5 = " \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"OQr\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}