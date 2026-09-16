rule _20160921_5ed9729c3ab2cb9d37d8a088af1aba59_20160921_b74bfd3dc740_5269 {
  meta:
    description = "datamaliciousorder - from files 20160921_5ed9729c3ab2cb9d37d8a088af1aba59.js, 20160921_b74bfd3dc7404d3d5a6512718aa52504.js, 20160921_de770f0ed114194a1a9d5e965c4fe675.js, 20160921_fa8c93ef210d8b4c6831cb1425f1dc9b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5908838424a9cae8eb5587cff7048056b427db1deb512dcbe9ca852a402e03d"
    hash2       = "359d333ab8fc51d27349ecaec71f8baf8e8aafae5bfe2d6afd26f4ed76e802db"
    hash3       = "57a3f4ba7362a09dfecfe27f6b8517c8290bc04a7020f4bbe4e9200a42655be0"
    hash4       = "7e7bb1d2ade80c23d5462f8e4a470a3c3245b07b8a709a3c911ff76a8c32da35"

  strings:
    $s1 = "n \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Ar\";})(),(fun" ascii
    $s2 = "fuck(){return \"IOs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"N" ascii
    $s3 = "n \"IPu\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"UOe\";})(),(fu" ascii
    $s4 = "n \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"XHj\";})(),(f" ascii
    $s5 = " fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"X" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}