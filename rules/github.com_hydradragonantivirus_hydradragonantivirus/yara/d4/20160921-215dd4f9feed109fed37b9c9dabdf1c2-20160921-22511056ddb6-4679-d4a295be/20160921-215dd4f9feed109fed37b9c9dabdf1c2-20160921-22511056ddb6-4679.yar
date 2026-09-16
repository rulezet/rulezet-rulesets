rule _20160921_215dd4f9feed109fed37b9c9dabdf1c2_20160921_22511056ddb6_4679 {
  meta:
    description = "datamaliciousorder - from files 20160921_215dd4f9feed109fed37b9c9dabdf1c2.js, 20160921_22511056ddb6d59ffb3e56c3b7382182.js, 20160921_3688778166acb8f4f21b3c1d67ada442.js, 20160921_56560f8d7ec61c150afb741a4a7975e2.js, 20160921_e78383c7f2f16b29dbde839d36607f19.js, 20160921_ef83849d63779003debb3d7ec32b193e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "710f88c7fda95a8d3e0e04de1ffd81606d227d249d76eb0d7fbeba7a0284a86e"
    hash2       = "1a5f7b2bfdf24defc0d363114441d0c0a0452fd599bf21d359b1b5f068dfc567"
    hash3       = "03559b6095f398f17a62ec1f50c0a70c4b4074a67f6b8e3a51dfe026b238b085"
    hash4       = "ba922e4e746eb45b8e98a88ec3071072c0850dbd5e2a359302331e1ae65210fb"
    hash5       = "3b18cb17d7caf150b505c169cb67d810f1ccee674cf86164682bf91d285bd02a"
    hash6       = "8c488afd3d971ee89eb15305d884bacb01b91fa70760bea0aaf808120622dfa3"

  strings:
    $s1 = "unction fuck(){return \"Za\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){ret" ascii
    $s2 = "tion fuck(){return \"LGo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){retur" ascii
    $s3 = "){return \"Yb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Np\";})" ascii
    $s4 = "return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"MOj\";})" ascii
    $s5 = "Sf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yb\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}