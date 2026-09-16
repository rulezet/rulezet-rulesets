rule _20160921_6db2cb585eb933d83d07b47d979b00ec_20160921_bfdb187f27d1_1601 {
  meta:
    description = "datamaliciousorder - from files 20160921_6db2cb585eb933d83d07b47d979b00ec.js, 20160921_bfdb187f27d136f64e05f0dcf2ee4914.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b98c5953d102d77c680619bcfd3ba762b3a28a14355f65c479544c745a7c9a12"
    hash2       = "cbf2173e7b067de6ce6bf189ba38c78f3f0d97a7e6685c0191e08885badfeb3e"

  strings:
    $s1  = "})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"RAi\";})(),(function fuck" ascii
    $s2  = "ction fuck(){return \"XCr\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return" ascii
    $s3  = "urn \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Np\";})(),(f" ascii
    $s4  = "(){return \"UOe\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"IOs\"" ascii
    $s5  = "h\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Ot\";})(),(function " ascii
    $s6  = "rn \"MBg\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"YAv\";})(),(fu" ascii
    $s7  = ",(function fuck(){return \"Wo\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){re" ascii
    $s8  = "unction fuck(){return \"Hs\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){ret" ascii
    $s9  = "ion fuck(){return \"IOs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return" ascii
    $s10 = "urn \"DRx\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Jg\";})(),(f" ascii
    $s11 = "DRx\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"ZVi\";})(),(functi" ascii
    $s12 = "})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"Jo\";})(),(function fuck(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}