rule _20160921_a210d5e93bf8b06dbd0a1b262abe210f_20160921_d414cec9501c_5603 {
  meta:
    description = "datamaliciousorder - from files 20160921_a210d5e93bf8b06dbd0a1b262abe210f.js, 20160921_d414cec9501c17802073a2f8f7b005c4.js, 20160921_dc73cfa7a33eb762f38614c69a95919d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "681408ae198939a760d376554e62f86e9d1fe2306266ffaee496dc9eed4d0687"
    hash2       = "65e6cb34b6f46aaa1020cec9a648634a1eceb7e9d6ad0387fc939923e8236594"
    hash3       = "50e80269adbbca38f500219eaf7cec16f396b3d8a7c56d342b2e4839819ea598"

  strings:
    $s1 = " fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"I" ascii
    $s2 = " \"Ug\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(func" ascii
    $s3 = "){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ar\";})" ascii
    $s4 = "k(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"USf\";" ascii
    $s5 = "on fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}