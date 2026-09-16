rule _20160921_5e78b76ea160d891abcb41db9983d51f_20160921_95c689d7ff47_5264 {
  meta:
    description = "datamaliciousorder - from files 20160921_5e78b76ea160d891abcb41db9983d51f.js, 20160921_95c689d7ff4700a03d604b71aaf3634b.js, 20160921_eda7773555acd8e0be7f4e8bf6d0b010.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "789149d5f226f5eb3642909acb465b5f94d946ee53a79d693b40f83359c4471f"
    hash2       = "5783f1dc6f93c438a9ac56abe49d6a41942b0b140e5fe608a7748f646ea646e7"
    hash3       = "af4e0a7c109ffa140c9db57a44bcd9c5d9b5a7c75daded0b422d2cec24c01c8b"

  strings:
    $s1 = "function fuck(){return \"IPu\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){ret" ascii
    $s2 = " \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"We\";})(),(funct" ascii
    $s3 = "eturn \"CTm\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Nm\";})()," ascii
    $s4 = "{return \"OQr\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"PDf\";})" ascii
    $s5 = " \"MBg\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ot\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}