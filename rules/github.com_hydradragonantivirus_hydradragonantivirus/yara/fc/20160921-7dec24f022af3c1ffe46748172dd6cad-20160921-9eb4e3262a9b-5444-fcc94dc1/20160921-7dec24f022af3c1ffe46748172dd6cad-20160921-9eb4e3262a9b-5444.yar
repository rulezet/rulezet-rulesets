rule _20160921_7dec24f022af3c1ffe46748172dd6cad_20160921_9eb4e3262a9b_5444 {
  meta:
    description = "datamaliciousorder - from files 20160921_7dec24f022af3c1ffe46748172dd6cad.js, 20160921_9eb4e3262a9bc5c5f03ba0b7b62a3347.js, 20160921_c42fb5c75aea2648513013ad2eed9aaf.js, 20160921_dc1ff053e9dd688459c33dc98e88d636.js, 20160921_f6f229e035b34b52398f9d713af3e947.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "402e919998fdba69cb3992879db4f947916245c38915db643643952fa450e947"
    hash2       = "03bf8e47f97cab996cc7f2d8147659dc1143ccbe1fd09af6b8689379f7263407"
    hash3       = "5c8cdf3dbb94e197c36e5744084d12e198ecdab7243d67654934aa1cc9bf7ae9"
    hash4       = "18a890096a5714e518b28d3f50f6487cfbc4164418daae1842b7d724e2c26bd6"
    hash5       = "dbd2ccfd17959ea084fe518e1748ca4f14e74a14593d7c157b17f4437f4336e3"

  strings:
    $s1 = "\"GJx\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s2 = ")(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ik\";})(),(function fuck" ascii
    $s3 = "(function fuck(){return \"Fv\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){r" ascii
    $s4 = "k(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"SUi\"" ascii
    $s5 = "IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"MUs\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}