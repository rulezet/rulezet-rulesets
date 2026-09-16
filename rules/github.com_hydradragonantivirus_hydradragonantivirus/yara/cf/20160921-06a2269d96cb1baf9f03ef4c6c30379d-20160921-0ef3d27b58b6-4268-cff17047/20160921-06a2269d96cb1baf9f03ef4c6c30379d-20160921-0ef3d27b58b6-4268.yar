rule _20160921_06a2269d96cb1baf9f03ef4c6c30379d_20160921_0ef3d27b58b6_4268 {
  meta:
    description = "datamaliciousorder - from files 20160921_06a2269d96cb1baf9f03ef4c6c30379d.js, 20160921_0ef3d27b58b620506f1d1320d2937789.js, 20160921_8dce9d2aa0d1e296bbcc31a437e35a45.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4904b4c397fdf3727eb6ad96b4ffc136ba26b2026b71428beeb74eac91fb976c"
    hash2       = "5e3dd80c1e1b35ce856eadc159cc2a53dce2adf2f9207a618bd73679e9d868b7"
    hash3       = "26c784fc7a8e4ee1608e66a82f1ba134972418c5968433b39f54392e7f3de0f2"

  strings:
    $s1 = ";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fu" ascii
    $s2 = "turn \"MBg\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"Vb\";})(),(" ascii
    $s3 = "(){return \"LGo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Qh\";}" ascii
    $s4 = "ction fuck(){return \"Dc\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return" ascii
    $s5 = "{return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"MOj\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}