rule _20160921_1363f95b1c666191b3b06b8bdde7d58c_20160921_1a0cb65a30f2_3371 {
  meta:
    description = "datamaliciousorder - from files 20160921_1363f95b1c666191b3b06b8bdde7d58c.js, 20160921_1a0cb65a30f2e052b2abb4edb6b853f4.js, 20160921_a8c002f684df9aec957f2a082ed80d84.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa3f648dc04a8b93f29d34ed8ee56d888b7b7469f9b81a0cc95a1d6f7ab8b098"
    hash2       = "cb576c42df90a554f241d4a5ba0dee1dfcb9caf661cf46a2800b743aa592e644"
    hash3       = "9db5f5694048d441a47fe4382700213cc288d4fba152eec7b99fdd310a50ef7d"

  strings:
    $s1 = "ion fuck(){return \"XFd\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return " ascii
    $s2 = "tion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){retur" ascii
    $s3 = "tion fuck(){return \"DAa\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return" ascii
    $s4 = "{return \"YQt\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Vf\";})(" ascii
    $s5 = "return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})" ascii
    $s6 = "ion fuck(){return \"Jh\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}