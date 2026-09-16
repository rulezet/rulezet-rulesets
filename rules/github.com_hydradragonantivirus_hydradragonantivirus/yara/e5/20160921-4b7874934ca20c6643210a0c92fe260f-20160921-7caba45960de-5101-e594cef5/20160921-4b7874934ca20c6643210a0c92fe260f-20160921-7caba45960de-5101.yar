rule _20160921_4b7874934ca20c6643210a0c92fe260f_20160921_7caba45960de_5101 {
  meta:
    description = "datamaliciousorder - from files 20160921_4b7874934ca20c6643210a0c92fe260f.js, 20160921_7caba45960de8ab0904dc3a8514f2614.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "858cb8ac4dab1ec1e6a2a0bb435765157525269e75820991212eee18a2d91717"
    hash2       = "f07b11e4aaeb00f3fa8863261ca37d382057c7775579fae2a5744dcfdb99cd95"

  strings:
    $s1 = "ion fuck(){return \"AUx\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s2 = "eturn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"AUx\";})(" ascii
    $s3 = "o0\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu\";})(),(functi" ascii
    $s4 = "ction fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){retur" ascii
    $s5 = "(){return \"FJs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Et\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}