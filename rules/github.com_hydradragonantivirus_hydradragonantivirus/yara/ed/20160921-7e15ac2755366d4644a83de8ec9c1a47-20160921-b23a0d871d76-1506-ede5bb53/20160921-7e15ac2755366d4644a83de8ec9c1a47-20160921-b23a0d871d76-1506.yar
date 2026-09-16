rule _20160921_7e15ac2755366d4644a83de8ec9c1a47_20160921_b23a0d871d76_1506 {
  meta:
    description = "datamaliciousorder - from files 20160921_7e15ac2755366d4644a83de8ec9c1a47.js, 20160921_b23a0d871d76c64a3c71f0b0f52faaa8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97eaf7c50f22bfc94f97a02e5e83a8f1fb3583717fb9f4a6666ae882ea4d6f55"
    hash2       = "02969139df11550b994530c0bcbc6d946b6e49105015e9475f5de3942d78e5a1"

  strings:
    $s1  = "\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Fv\";})(),(function " ascii
    $s2  = "nction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){retur" ascii
    $s3  = "(){return \"Mw\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";" ascii
    $s4  = "unction fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){ret" ascii
    $s5  = "n \"Np\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Jo\";})(),(func" ascii
    $s6  = "(){return \"Ik\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"MUs\";}" ascii
    $s7  = "tion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return" ascii
    $s8  = "ck(){return \"Ar\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\"" ascii
    $s9  = "ion fuck(){return \"ZLd\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return " ascii
    $s10 = "(),(function fuck(){return \"USf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Hs\";})(),(function fuck(" ascii
    $s11 = ";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Cd\";})(),(function fu" ascii
    $s12 = "n fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"" ascii
    $s13 = "{return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Ve\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}