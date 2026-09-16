rule _20160921_214342143d6b7e971a1c8d2679379cb7_20160921_215dd4f9feed_4674 {
  meta:
    description = "datamaliciousorder - from files 20160921_214342143d6b7e971a1c8d2679379cb7.js, 20160921_215dd4f9feed109fed37b9c9dabdf1c2.js, 20160921_5e9244484429cd897ec88fe97140c29c.js, 20160921_e6b8063519cd61bbba9375bf86215501.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8dcc208c118a95c2f88df14e844ed832ee1e06bdf992329e8a721bd7aaa936e8"
    hash2       = "710f88c7fda95a8d3e0e04de1ffd81606d227d249d76eb0d7fbeba7a0284a86e"
    hash3       = "002e6ee9d0d9e7f54ead7f8981f20be210819f7a75c52e3d1e91de2fd03ada17"
    hash4       = "70ad2f9c8f844d4c80b1d4ce0f71f62f74e64671ae11d2d3af8e6ec764993403"

  strings:
    $s1 = "){return \"UOe\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";}" ascii
    $s2 = "eturn \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})()" ascii
    $s3 = "rn \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"NKq\";})(),(fu" ascii
    $s4 = "ction fuck(){return \"IKv\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){retur" ascii
    $s5 = "unction fuck(){return \"USf\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}