rule _20160921_17bab7cc945fd06123e7b9b16dea263f_20160921_570295874dae_2744 {
  meta:
    description = "datamaliciousorder - from files 20160921_17bab7cc945fd06123e7b9b16dea263f.js, 20160921_570295874daef65ccf11d909395ae377.js, 20160921_edb059fcf68869f74200cd1e68a29bc4.js, 20160922_c593174721c6fbd1b57bf98d8a85a6fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1dd80ed4e2509af999afcf84c8f78ecc409616f9d6e072d25cb980d8bf9e464"
    hash2       = "a5b27b9fc0152c3186c53a02507be373440217ec70f24fc85249bdaebbeb5494"
    hash3       = "9851e93d2e92fdd3882a14c4f00aface7bdc1495b43f7a98040092131f600e38"
    hash4       = "c85cab0d5b0c79fe38ee2b60c2ea7eca36bb7dbe9442cff0a497346184cecee8"

  strings:
    $s1 = "f000(){return \"Kw\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KX" ascii
    $s2 = "00(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"DYx" ascii
    $s3 = "{return \"ZFe\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})" ascii
    $s4 = "GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Wb\";})(),(functi" ascii
    $s5 = "{return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"GGn\";}" ascii
    $s6 = "function f000(){return \"QDg\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"NBs\";})(),(function f000(){re" ascii
    $s7 = "n f000(){return \"Vj\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Yi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}