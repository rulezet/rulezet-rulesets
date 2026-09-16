rule _20160921_5ed9729c3ab2cb9d37d8a088af1aba59_20160921_b74bfd3dc740_5270 {
  meta:
    description = "datamaliciousorder - from files 20160921_5ed9729c3ab2cb9d37d8a088af1aba59.js, 20160921_b74bfd3dc7404d3d5a6512718aa52504.js, 20160921_bfdb187f27d136f64e05f0dcf2ee4914.js, 20160921_fa8c93ef210d8b4c6831cb1425f1dc9b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5908838424a9cae8eb5587cff7048056b427db1deb512dcbe9ca852a402e03d"
    hash2       = "359d333ab8fc51d27349ecaec71f8baf8e8aafae5bfe2d6afd26f4ed76e802db"
    hash3       = "cbf2173e7b067de6ce6bf189ba38c78f3f0d97a7e6685c0191e08885badfeb3e"
    hash4       = "7e7bb1d2ade80c23d5462f8e4a470a3c3245b07b8a709a3c911ff76a8c32da35"

  strings:
    $s1 = "),(function fuck(){return \"USf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(" ascii
    $s2 = "unction fuck(){return \"MBg\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){ret" ascii
    $s3 = "turn \"TTs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s4 = "Ai\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(functio" ascii
    $s5 = "){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Np\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}