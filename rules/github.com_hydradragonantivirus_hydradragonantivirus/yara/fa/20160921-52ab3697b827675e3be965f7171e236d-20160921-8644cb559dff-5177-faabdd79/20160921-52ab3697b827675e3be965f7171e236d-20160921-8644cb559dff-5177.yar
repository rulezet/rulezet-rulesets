rule _20160921_52ab3697b827675e3be965f7171e236d_20160921_8644cb559dff_5177 {
  meta:
    description = "datamaliciousorder - from files 20160921_52ab3697b827675e3be965f7171e236d.js, 20160921_8644cb559dff4747b398e56be3b4ea85.js, 20160921_8a4a5c81c02126f78061e6b947b8f9bc.js, 20160921_c6bbdc353079233dc4959e9d0d85bc2d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90a876a1d91ded80337b02adca1c227fdf5b5a96381a62397d3485e5e8ea108b"
    hash2       = "d92ab3635a987485347ef1a40e84d56adf54d5da5be50490856e0386b6ccabda"
    hash3       = "3543e3d5dddde5efe5675e5ec649f9614fc6d9e81a903f893466af300e1dc64b"
    hash4       = "6fbb4e2c3fc90d9c1f39093c60f9a0294627c14ec844d16cb99b4f2b5fc1c158"

  strings:
    $s1 = "ck(){return \"IPu\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"LGo" ascii
    $s2 = "turn \"MUs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()" ascii
    $s3 = "turn \"Wo\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"TTs\";})()," ascii
    $s4 = "\"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";})(),(fun" ascii
    $s5 = "(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Qh\";})(),(function fuck(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}