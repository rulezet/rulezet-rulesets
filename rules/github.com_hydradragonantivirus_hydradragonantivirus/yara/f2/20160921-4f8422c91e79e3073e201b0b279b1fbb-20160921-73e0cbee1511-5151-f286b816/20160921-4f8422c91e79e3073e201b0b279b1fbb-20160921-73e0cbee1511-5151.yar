rule _20160921_4f8422c91e79e3073e201b0b279b1fbb_20160921_73e0cbee1511_5151 {
  meta:
    description = "datamaliciousorder - from files 20160921_4f8422c91e79e3073e201b0b279b1fbb.js, 20160921_73e0cbee151147d27e01ecc015f640b4.js, 20160921_7c5b5eaba938fa91eb6a9414212e13f9.js, 20160921_c979e38640433b8c93e1c145417c85cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1cc54af4d213d0cd37c81b29d25c29bf00892e3458ef2e236563c69fd58b94a"
    hash2       = "0ad4b632b07e5e4526b874097c116e5183b155ec4b9cf40e3f13ece0ce027344"
    hash3       = "9b25331c24a00cfccf7bf1604f7df1d245543734bf5553f0a7c3c911bb74cbb8"
    hash4       = "62a468202853ba6a8adb456e8c12b66f8794360c094a85e6d4d2cf43d13a75ce"

  strings:
    $s1 = "nction fuck(){return \"DAa\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){ret" ascii
    $s2 = "urn \"MBg\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"GWo\";})(),(" ascii
    $s3 = " fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"P" ascii
    $s4 = " \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Jh\";})(),(funct" ascii
    $s5 = "})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"LGo\";})(),(function fuc" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}