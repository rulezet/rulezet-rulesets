rule _20160921_0f4dee7115fed314f330d52696c0d1d1_20160921_30902cdec8af_410 {
  meta:
    description = "datamaliciousorder - from files 20160921_0f4dee7115fed314f330d52696c0d1d1.js, 20160921_30902cdec8afbffc64d0c0cd57e17570.js, 20160921_87978dcbc3a23f5dbd5fc73bee04f432.js, 20160921_a84d89efd5400c906c1132a56b0ef679.js, 20160921_c58f55b02ed5bcc68d14314fe1cbe1f0.js, 20160921_de03e8e8d98da4b7d17147c979ce9ff8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dec7336f5db71057e4227c26b20731cd69ad29c7628e161fff2f7964754477b1"
    hash2       = "794f51b8ce9ffbf2858ed5522e027d4ca3155be961907d88f09dd5679b3f1a18"
    hash3       = "a6d96c94cf7f327ade629dec6f41b2fcfa7f7accfa8da780df3fea48273270dd"
    hash4       = "f3cfecdabdf17d9af410d0fee7ec88844bc361668aca1a114832bd3e515d3456"
    hash5       = "9b14dd6c2f6263aca7c445e6160fdf64ae8e12248f26b67576668dd3b4f18382"
    hash6       = "aa4eb617dd497a7ea1d016d98ce4ca8e81e13b4e240c42d46d01e84e617a150b"

  strings:
    $s1  = "uck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Jh\"" ascii
    $s2  = "function fuck(){return \"Ot\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s3  = "(){return \"FJs\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";}" ascii
    $s4  = "h\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Ot\";})(),(function " ascii
    $s5  = "Xg\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"SUi\";})(),(functio" ascii
    $s6  = "KVh\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(functi" ascii
    $s7  = "(),(function fuck(){return \"LLv\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Jg\";})(),(function fuck(" ascii
    $s8  = "k(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Ar\";" ascii
    $s9  = "t\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Cd\";})(),(function f" ascii
    $s10 = "k(){return \"To\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Fv\";})" ascii
    $s11 = "(){return \"Pc\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})" ascii
    $s12 = "\"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xw\";})(),(functio" ascii
    $s13 = "n \"Xw\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Hs\";})(),(func" ascii
    $s14 = "n fuck(){return \"Xw\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"" ascii
    $s15 = "fuck(){return \"Wo\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"LG" ascii
    $s16 = "uck(){return \"VMi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Xw\"" ascii
    $s17 = "on fuck(){return \"YAv\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return " ascii
    $s18 = "nction fuck(){return \"Av\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii
    $s19 = "})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Oh\";})(),(function fuck(" ascii
    $s20 = "return \"To\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"EHo\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}