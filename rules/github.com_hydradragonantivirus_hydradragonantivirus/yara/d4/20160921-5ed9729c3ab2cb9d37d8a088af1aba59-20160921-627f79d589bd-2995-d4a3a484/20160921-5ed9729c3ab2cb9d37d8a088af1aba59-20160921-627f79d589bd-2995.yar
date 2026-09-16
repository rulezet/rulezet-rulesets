rule _20160921_5ed9729c3ab2cb9d37d8a088af1aba59_20160921_627f79d589bd_2995 {
  meta:
    description = "datamaliciousorder - from files 20160921_5ed9729c3ab2cb9d37d8a088af1aba59.js, 20160921_627f79d589bde52c443bc2d40f887ced.js, 20160921_b0c04db09e980eb82ccee9091ca50467.js, 20160921_b74bfd3dc7404d3d5a6512718aa52504.js, 20160921_c779962dc8b38bbb280b695e631131fa.js, 20160921_e6771cfa257410eb61913de76cb777a8.js, 20160921_fa8c93ef210d8b4c6831cb1425f1dc9b.js, 20160921_fc08be0621d4ffbced0eaca2b2622b07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5908838424a9cae8eb5587cff7048056b427db1deb512dcbe9ca852a402e03d"
    hash2       = "f23a9d984b71a422ca30ec7f94f4a4cb0a2303699dc80edbced4a4c608e370e4"
    hash3       = "9e020a4a8174eebc9bdfd2c370a1a8a86e255e968f9dc218329e9d5912ba227b"
    hash4       = "359d333ab8fc51d27349ecaec71f8baf8e8aafae5bfe2d6afd26f4ed76e802db"
    hash5       = "cf3f9e3180d8fa16719dbea90d762850a1742512c7be6bc42325dc9e094add30"
    hash6       = "009074e75815902f1e36daa21c179598b761767cd8d92eb363f3541838abdbfe"
    hash7       = "7e7bb1d2ade80c23d5462f8e4a470a3c3245b07b8a709a3c911ff76a8c32da35"
    hash8       = "1641412d2cba74b5cd1b4c4619c995601c42039d472339eb7cb10d97e1d47339"

  strings:
    $s1 = "eturn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"USf\";})(" ascii
    $s2 = "),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){r" ascii
    $s3 = "k(){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"NKq\";" ascii
    $s4 = "eturn \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(" ascii
    $s5 = "eturn \"IPu\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Fv\";})(),(" ascii
    $s6 = "ion fuck(){return \"MBg\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return" ascii
    $s7 = "fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IP" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}