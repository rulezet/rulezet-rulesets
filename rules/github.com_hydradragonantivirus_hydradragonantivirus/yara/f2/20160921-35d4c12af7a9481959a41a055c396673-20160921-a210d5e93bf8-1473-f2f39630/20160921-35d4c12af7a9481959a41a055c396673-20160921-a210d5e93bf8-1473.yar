rule _20160921_35d4c12af7a9481959a41a055c396673_20160921_a210d5e93bf8_1473 {
  meta:
    description = "datamaliciousorder - from files 20160921_35d4c12af7a9481959a41a055c396673.js, 20160921_a210d5e93bf8b06dbd0a1b262abe210f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c2412951fad30bb8b34aca279acd07c03a437936261b0d90334331b98cf1e99"
    hash2       = "681408ae198939a760d376554e62f86e9d1fe2306266ffaee496dc9eed4d0687"

  strings:
    $s1  = "})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"AUx\";})(),(function fuc" ascii
    $s2  = "urn \"Xg\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(f" ascii
    $s3  = "{return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"RAi\";})" ascii
    $s4  = "uck(){return \"Ot\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"IPu\"" ascii
    $s5  = "uck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"GWo" ascii
    $s6  = "(){return \"MBg\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Jh\";})" ascii
    $s7  = "unction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){ret" ascii
    $s8  = "ck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"LGo" ascii
    $s9  = "ck(){return \"Jo\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Py\"" ascii
    $s10 = " fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"G" ascii
    $s11 = "n fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return " ascii
    $s12 = "urn \"Py\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s13 = "tion fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}