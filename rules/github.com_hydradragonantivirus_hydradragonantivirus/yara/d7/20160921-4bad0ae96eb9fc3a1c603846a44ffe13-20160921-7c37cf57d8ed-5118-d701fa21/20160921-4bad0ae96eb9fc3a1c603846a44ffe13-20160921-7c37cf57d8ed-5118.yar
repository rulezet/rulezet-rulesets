rule _20160921_4bad0ae96eb9fc3a1c603846a44ffe13_20160921_7c37cf57d8ed_5118 {
  meta:
    description = "datamaliciousorder - from files 20160921_4bad0ae96eb9fc3a1c603846a44ffe13.js, 20160921_7c37cf57d8ed1c10fea15c60dc79c0c8.js, 20160921_832521e32124647e5f9543472346f319.js, 20160921_cda776f6c5cb6eec510c00d5294fbfae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a99f235f58613323f5c58def3503d47959f4a77f0697e30c75b6d221c4b40806"
    hash2       = "c3acecff4ec35ade7d618cbd511372d6023de7d591317c5e6ce95fc088b8cf6e"
    hash3       = "7d8db496c31215a3730a6ed92a0e2b36ff0fe0e9ddaf7405680d1002474263e1"
    hash4       = "064df16cff12584bccc68fb79fe80908e6edeb4ccf32c3c0b6a79b8b0424820c"

  strings:
    $s1 = "(function fuck(){return \"GJx\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){r" ascii
    $s2 = "ion fuck(){return \"Vb\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s3 = "uck(){return \"Ot\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"OQr" ascii
    $s4 = "ion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return " ascii
    $s5 = "{return \"XHj\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}