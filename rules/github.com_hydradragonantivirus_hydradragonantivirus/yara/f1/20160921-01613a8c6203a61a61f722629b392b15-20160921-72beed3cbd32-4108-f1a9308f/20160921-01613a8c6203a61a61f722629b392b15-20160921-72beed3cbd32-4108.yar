rule _20160921_01613a8c6203a61a61f722629b392b15_20160921_72beed3cbd32_4108 {
  meta:
    description = "datamaliciousorder - from files 20160921_01613a8c6203a61a61f722629b392b15.js, 20160921_72beed3cbd321b62d224a35a01639682.js, 20160921_d03dc2f478ae343430b4a6dbcc9d6c08.js, 20160921_f1bb498dcbb1f3aecbc35886be394f58.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c3ee763f1740e8bc6ded9772aabbe3d3805d8cf2a023e0289a9b8a1a42624b7"
    hash2       = "ce3c3a93d2e5df0f850da4d79a5f697eaff66f1043058d62f80adad98b476839"
    hash3       = "dd1077874fb7f556e5acfe2ff0c2ed6b6c203fcdf442119ca307096446d90cd4"
    hash4       = "486454370a5dac6af41bfda9ac339e37120334ce5f7c4319bd0f8e9df9514b44"

  strings:
    $s1 = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){retur" ascii
    $s2 = "){return \"OQr\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Cd\";})" ascii
    $s3 = "return \"GNm\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})" ascii
    $s4 = "uck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Cd" ascii
    $s5 = "tion fuck(){return \"PDf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}