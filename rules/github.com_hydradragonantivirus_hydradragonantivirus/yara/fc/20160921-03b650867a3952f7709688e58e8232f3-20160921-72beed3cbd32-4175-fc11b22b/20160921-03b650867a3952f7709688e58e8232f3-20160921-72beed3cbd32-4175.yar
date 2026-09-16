rule _20160921_03b650867a3952f7709688e58e8232f3_20160921_72beed3cbd32_4175 {
  meta:
    description = "datamaliciousorder - from files 20160921_03b650867a3952f7709688e58e8232f3.js, 20160921_72beed3cbd321b62d224a35a01639682.js, 20160921_a210d5e93bf8b06dbd0a1b262abe210f.js, 20160921_dc73cfa7a33eb762f38614c69a95919d.js, 20160921_f1bb498dcbb1f3aecbc35886be394f58.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a775853212fe6663d7c077a64c0d4c851d4b7f261a6c0846b4552b556e12a5fe"
    hash2       = "ce3c3a93d2e5df0f850da4d79a5f697eaff66f1043058d62f80adad98b476839"
    hash3       = "681408ae198939a760d376554e62f86e9d1fe2306266ffaee496dc9eed4d0687"
    hash4       = "50e80269adbbca38f500219eaf7cec16f396b3d8a7c56d342b2e4839819ea598"
    hash5       = "486454370a5dac6af41bfda9ac339e37120334ce5f7c4319bd0f8e9df9514b44"

  strings:
    $s1 = "ion fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return" ascii
    $s2 = "n \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"KVh\";})(),(f" ascii
    $s3 = "{return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"UXf\";})(" ascii
    $s4 = "n fuck(){return \"Fv\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"D" ascii
    $s5 = "(function fuck(){return \"Ot\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}