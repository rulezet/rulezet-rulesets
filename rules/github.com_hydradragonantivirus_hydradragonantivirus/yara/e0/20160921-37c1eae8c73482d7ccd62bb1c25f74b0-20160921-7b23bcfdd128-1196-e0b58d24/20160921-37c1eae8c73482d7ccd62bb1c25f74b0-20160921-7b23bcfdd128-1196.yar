rule _20160921_37c1eae8c73482d7ccd62bb1c25f74b0_20160921_7b23bcfdd128_1196 {
  meta:
    description = "datamaliciousorder - from files 20160921_37c1eae8c73482d7ccd62bb1c25f74b0.js, 20160921_7b23bcfdd1289634cd9a4c73f4cbb144.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e724c0f7c8722eec82dd0f37b13b38ab5c357aeccb2cc6c36efae80bae66a8a"
    hash2       = "7a94fbc46ac51a544406f9a59bf405cd1e19e8e6681d7feacbc81e5ab7d4a50b"

  strings:
    $s1  = "s\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Hs\";})(),(function f" ascii
    $s2  = "unction fuck(){return \"Ml\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){ret" ascii
    $s3  = "ck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Xg" ascii
    $s4  = "on fuck(){return \"SUi\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return " ascii
    $s5  = "ction fuck(){return \"Ik\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){retur" ascii
    $s6  = "(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Yk\";})(),(function fuck()" ascii
    $s7  = "{return \"Xg\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Av\";})()" ascii
    $s8  = "n \"OQr\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"UOe\";})(),(fun" ascii
    $s9  = "ion fuck(){return \"ZWu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return " ascii
    $s10 = "eturn \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Xw\";})()," ascii
    $s11 = "n \"MUs\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s12 = "),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Za\";})(),(function fuck(){" ascii
    $s13 = "k(){return \"Sx\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\"" ascii
    $s14 = "ction fuck(){return \"UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){retu" ascii
    $s15 = "return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"FJs\";})(" ascii
    $s16 = "Js\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"ZVi\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}