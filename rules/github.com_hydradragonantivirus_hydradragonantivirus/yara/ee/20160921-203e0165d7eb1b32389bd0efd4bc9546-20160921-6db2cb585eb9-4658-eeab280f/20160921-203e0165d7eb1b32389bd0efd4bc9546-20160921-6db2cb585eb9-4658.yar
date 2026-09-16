rule _20160921_203e0165d7eb1b32389bd0efd4bc9546_20160921_6db2cb585eb9_4658 {
  meta:
    description = "datamaliciousorder - from files 20160921_203e0165d7eb1b32389bd0efd4bc9546.js, 20160921_6db2cb585eb933d83d07b47d979b00ec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9112c30f4cc79af123a3f3e13b1e01a29f2419955988701cb25a673fdfe684d"
    hash2       = "b98c5953d102d77c680619bcfd3ba762b3a28a14355f65c479544c745a7c9a12"

  strings:
    $s1 = "ion fuck(){return \"Et\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return " ascii
    $s2 = "nction fuck(){return \"Et\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){retu" ascii
    $s3 = "urn \"UXf\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Za\";})(),(f" ascii
    $s4 = "(),(function fuck(){return \"Za\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"We\";})(),(function fuck()" ascii
    $s5 = "\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"DRx\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}