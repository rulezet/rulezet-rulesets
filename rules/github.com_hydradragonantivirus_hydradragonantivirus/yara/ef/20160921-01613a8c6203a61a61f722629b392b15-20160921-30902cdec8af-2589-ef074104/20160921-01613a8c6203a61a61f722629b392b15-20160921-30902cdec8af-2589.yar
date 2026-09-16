rule _20160921_01613a8c6203a61a61f722629b392b15_20160921_30902cdec8af_2589 {
  meta:
    description = "datamaliciousorder - from files 20160921_01613a8c6203a61a61f722629b392b15.js, 20160921_30902cdec8afbffc64d0c0cd57e17570.js, 20160921_c58f55b02ed5bcc68d14314fe1cbe1f0.js, 20160921_d03dc2f478ae343430b4a6dbcc9d6c08.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c3ee763f1740e8bc6ded9772aabbe3d3805d8cf2a023e0289a9b8a1a42624b7"
    hash2       = "794f51b8ce9ffbf2858ed5522e027d4ca3155be961907d88f09dd5679b3f1a18"
    hash3       = "9b14dd6c2f6263aca7c445e6160fdf64ae8e12248f26b67576668dd3b4f18382"
    hash4       = "dd1077874fb7f556e5acfe2ff0c2ed6b6c203fcdf442119ca307096446d90cd4"

  strings:
    $s1 = "{return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Yk\";})" ascii
    $s2 = ",(function fuck(){return \"IOs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function fuck()" ascii
    $s3 = "ck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"ZVi" ascii
    $s4 = "Av\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ug\";})(),(function " ascii
    $s5 = "\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s6 = "fuck(){return \"CCb\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"CC" ascii
    $s7 = "{return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Cd\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}