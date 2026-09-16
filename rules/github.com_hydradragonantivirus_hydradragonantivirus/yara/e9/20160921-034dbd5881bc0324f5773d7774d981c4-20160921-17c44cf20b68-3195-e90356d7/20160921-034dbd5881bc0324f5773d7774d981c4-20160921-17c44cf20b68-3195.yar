rule _20160921_034dbd5881bc0324f5773d7774d981c4_20160921_17c44cf20b68_3195 {
  meta:
    description = "datamaliciousorder - from files 20160921_034dbd5881bc0324f5773d7774d981c4.js, 20160921_17c44cf20b688f3f5be613056d39409e.js, 20160921_4f1da2d661fb97b4733f3fbf35efff6c.js, 20160921_dbc1b5f3d0381a2cf3968267e55b6f78.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82795298a84df6fa0b0e45225727206f9a173f55589db6b76ab8df4198dc55c7"
    hash2       = "0a10c81cc5c3cc9eb38f73af3b77ed314fed047818a2410613c91431eee6bee1"
    hash3       = "57198460b755f2336c23ed27d26f09514db08ab180e216293a853489286f4ff2"
    hash4       = "e37cb576da589586ca091f887f2d941f81f58c7a8c3974b4e11928357dfee825"

  strings:
    $s1 = "nction fuck(){return \"Jo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s2 = "uck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"NK" ascii
    $s3 = "return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";})(" ascii
    $s4 = "ion fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii
    $s5 = "ion fuck(){return \"MBg\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return " ascii
    $s6 = "tion fuck(){return \"Xw\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}