rule _20160921_034dbd5881bc0324f5773d7774d981c4_20160921_0ae28061d65a_4162 {
  meta:
    description = "datamaliciousorder - from files 20160921_034dbd5881bc0324f5773d7774d981c4.js, 20160921_0ae28061d65a12c6450dddd9c44f7998.js, 20160921_17c44cf20b688f3f5be613056d39409e.js, 20160921_4f1da2d661fb97b4733f3fbf35efff6c.js, 20160921_5c9dd9a0e8a8b3e5e8713af8aeaa5d59.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82795298a84df6fa0b0e45225727206f9a173f55589db6b76ab8df4198dc55c7"
    hash2       = "2262aefc89b27a9a5b4507f43a6978eafd72ba25a305a11cdeb589d958f0e0a6"
    hash3       = "0a10c81cc5c3cc9eb38f73af3b77ed314fed047818a2410613c91431eee6bee1"
    hash4       = "57198460b755f2336c23ed27d26f09514db08ab180e216293a853489286f4ff2"
    hash5       = "415a66b711143ada4e334e2da2ea19ca0e94ec191118672a58fa21828a1cd877"

  strings:
    $s1 = "tion fuck(){return \"ZWu\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s2 = "n fuck(){return \"ADy\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return " ascii
    $s3 = "})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"EHo\";})(),(function fuc" ascii
    $s4 = "on fuck(){return \"Wo\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"" ascii
    $s5 = "eturn \"XHj\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Vf\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}