rule _20160921_203e0165d7eb1b32389bd0efd4bc9546_20160921_2c106cc001da_3498 {
  meta:
    description = "datamaliciousorder - from files 20160921_203e0165d7eb1b32389bd0efd4bc9546.js, 20160921_2c106cc001daa2dffdfde7e2aa5c908b.js, 20160921_3823f4aff4d341a62056d936e59de44c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9112c30f4cc79af123a3f3e13b1e01a29f2419955988701cb25a673fdfe684d"
    hash2       = "ca5356b92abf859d45d843749f45e5e06c7d045b4e7ea5d215ab87cdb8c8f66b"
    hash3       = "d0b475c02138425371c1df69faa8ac5c3d739764950c4a65034372b4455ac04d"

  strings:
    $s1 = ",(function fuck(){return \"USf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck()" ascii
    $s2 = "i\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(function" ascii
    $s3 = "uck(){return \"ADy\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"RA" ascii
    $s4 = "{return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Np\";})()" ascii
    $s5 = "nction fuck(){return \"MBg\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){retu" ascii
    $s6 = "urn \"TTs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}