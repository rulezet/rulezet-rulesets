rule _20160921_01da6b0c1b5614c5877e0dd7b6be4036_20160921_17642c69cbfb_4124 {
  meta:
    description = "datamaliciousorder - from files 20160921_01da6b0c1b5614c5877e0dd7b6be4036.js, 20160921_17642c69cbfb276056f3695ae22dad4c.js, 20160921_5ed9729c3ab2cb9d37d8a088af1aba59.js, 20160921_b74bfd3dc7404d3d5a6512718aa52504.js, 20160921_fa8c93ef210d8b4c6831cb1425f1dc9b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5da941f7d098e0926acf7ad9efedc9f91495115fc83f288580eba79e44574693"
    hash2       = "4cdbf9fba4e3fec424cf182fd21fa3c400b0649ca09f140375a47df12248955c"
    hash3       = "c5908838424a9cae8eb5587cff7048056b427db1deb512dcbe9ca852a402e03d"
    hash4       = "359d333ab8fc51d27349ecaec71f8baf8e8aafae5bfe2d6afd26f4ed76e802db"
    hash5       = "7e7bb1d2ade80c23d5462f8e4a470a3c3245b07b8a709a3c911ff76a8c32da35"

  strings:
    $s1 = "){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"ADy\";" ascii
    $s2 = "tion fuck(){return \"Vb\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return " ascii
    $s3 = "k(){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"USf" ascii
    $s4 = "nction fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){ret" ascii
    $s5 = "p\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Vb\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}