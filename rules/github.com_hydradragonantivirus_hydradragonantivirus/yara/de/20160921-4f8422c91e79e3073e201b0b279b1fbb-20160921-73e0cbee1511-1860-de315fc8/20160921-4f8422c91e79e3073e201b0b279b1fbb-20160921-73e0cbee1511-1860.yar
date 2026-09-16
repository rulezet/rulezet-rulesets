rule _20160921_4f8422c91e79e3073e201b0b279b1fbb_20160921_73e0cbee1511_1860 {
  meta:
    description = "datamaliciousorder - from files 20160921_4f8422c91e79e3073e201b0b279b1fbb.js, 20160921_73e0cbee151147d27e01ecc015f640b4.js, 20160921_91734b00fd54cd3dd10c5f20c35d7864.js, 20160921_c979e38640433b8c93e1c145417c85cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1cc54af4d213d0cd37c81b29d25c29bf00892e3458ef2e236563c69fd58b94a"
    hash2       = "0ad4b632b07e5e4526b874097c116e5183b155ec4b9cf40e3f13ece0ce027344"
    hash3       = "cdae8af0c395dfe20c83f759c05d2fd6ae2859606871798c6b3a7a12257c7f70"
    hash4       = "62a468202853ba6a8adb456e8c12b66f8794360c094a85e6d4d2cf43d13a75ce"

  strings:
    $s1  = "ck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Cd\"" ascii
    $s2  = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return" ascii
    $s3  = "unction fuck(){return \"SUi\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s4  = " \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"SUi\";})(),(fun" ascii
    $s5  = "(){return \"ZWu\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\"" ascii
    $s6  = "function fuck(){return \"Et\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){ret" ascii
    $s7  = "eturn \"ZWu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Np\";})(),(" ascii
    $s8  = "fuck(){return \"Ai\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"RAi" ascii
    $s9  = "(){return \"GJx\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"IPu\";}" ascii
    $s10 = "unction fuck(){return \"XFd\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}