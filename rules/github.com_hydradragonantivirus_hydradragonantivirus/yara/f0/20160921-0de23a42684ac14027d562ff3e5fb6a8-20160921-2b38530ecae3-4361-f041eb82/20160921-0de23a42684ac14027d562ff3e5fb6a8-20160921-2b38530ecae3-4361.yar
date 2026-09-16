rule _20160921_0de23a42684ac14027d562ff3e5fb6a8_20160921_2b38530ecae3_4361 {
  meta:
    description = "datamaliciousorder - from files 20160921_0de23a42684ac14027d562ff3e5fb6a8.js, 20160921_2b38530ecae3735e98453e56dd7a0292.js, 20160921_48288731baa006b25b4e98b12520da2b.js, 20160921_759ae57c0ca15acf993d43f7b7e2485d.js, 20160921_8dce9d2aa0d1e296bbcc31a437e35a45.js, 20160921_dc67677da64e0c03fb55538663264839.js, 20160921_de770f0ed114194a1a9d5e965c4fe675.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7237be0906b854ec3890943cde0c9a731117b836078be4256fe37413dd372a66"
    hash2       = "46f1595f803e301ed13d99315b244aac664f908c0c0d8ab508c1d104bf7ae947"
    hash3       = "ce917015afcf31459cc47b8864f85394a756701f6338f6a2cbe079779c3ecd43"
    hash4       = "d9d1c0189a6de533e712d41961659591f07faec880d17e164eed8e8084710d25"
    hash5       = "26c784fc7a8e4ee1608e66a82f1ba134972418c5968433b39f54392e7f3de0f2"
    hash6       = "0421d641ee833363b2481952ecbaff1400ca62443adb847ffe03bed95e4077f8"
    hash7       = "57a3f4ba7362a09dfecfe27f6b8517c8290bc04a7020f4bbe4e9200a42655be0"

  strings:
    $s1 = "rn \"Hs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(fu" ascii
    $s2 = "u\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Hs\";})(),(function " ascii
    $s3 = "k(){return \"ADy\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\"" ascii
    $s4 = "eturn \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(" ascii
    $s5 = "(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}