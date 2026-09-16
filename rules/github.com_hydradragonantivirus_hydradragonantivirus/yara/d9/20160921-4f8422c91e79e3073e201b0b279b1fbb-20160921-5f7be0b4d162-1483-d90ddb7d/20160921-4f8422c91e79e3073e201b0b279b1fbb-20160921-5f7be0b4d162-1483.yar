rule _20160921_4f8422c91e79e3073e201b0b279b1fbb_20160921_5f7be0b4d162_1483 {
  meta:
    description = "datamaliciousorder - from files 20160921_4f8422c91e79e3073e201b0b279b1fbb.js, 20160921_5f7be0b4d162caa40e1fc5a06f9f867a.js, 20160921_73e0cbee151147d27e01ecc015f640b4.js, 20160921_c979e38640433b8c93e1c145417c85cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1cc54af4d213d0cd37c81b29d25c29bf00892e3458ef2e236563c69fd58b94a"
    hash2       = "9a6e02fec1a6c5d0a6813da97edfb28eb017c5563b8e8c2205eb08ae1c6ec4e3"
    hash3       = "0ad4b632b07e5e4526b874097c116e5183b155ec4b9cf40e3f13ece0ce027344"
    hash4       = "62a468202853ba6a8adb456e8c12b66f8794360c094a85e6d4d2cf43d13a75ce"

  strings:
    $s1  = "return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})" ascii
    $s2  = ")(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"USf\";})(),(function fuc" ascii
    $s3  = "fuck(){return \"RAi\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"I" ascii
    $s4  = "{return \"ZLd\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"IPu\";})" ascii
    $s5  = "function fuck(){return \"IKv\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){re" ascii
    $s6  = "tion fuck(){return \"Mw\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s7  = "o\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"GNm\";})(),(functio" ascii
    $s8  = "){return \"Qh\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";}" ascii
    $s9  = " fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"L" ascii
    $s10 = "on fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return " ascii
    $s11 = "ck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yb\"" ascii
    $s12 = "ction fuck(){return \"IRn\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){retu" ascii
    $s13 = "unction fuck(){return \"Yb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}