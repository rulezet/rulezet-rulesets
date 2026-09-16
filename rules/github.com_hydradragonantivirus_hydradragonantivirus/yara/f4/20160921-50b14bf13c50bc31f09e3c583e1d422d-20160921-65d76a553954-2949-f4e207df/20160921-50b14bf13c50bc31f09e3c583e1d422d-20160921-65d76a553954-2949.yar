rule _20160921_50b14bf13c50bc31f09e3c583e1d422d_20160921_65d76a553954_2949 {
  meta:
    description = "datamaliciousorder - from files 20160921_50b14bf13c50bc31f09e3c583e1d422d.js, 20160921_65d76a5539546b98145997b9a44c1a09.js, 20160921_ce3c0604d52e9dc9119cefedfee34385.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9aab1a9f889ee14c72c5b3718595b8a66b04e749b1cb75ceb264874c173aeab"
    hash2       = "0a1b81d7435f521382a4cec07d80cbc8fe75f2ebac92fb6c4d105b19ec098560"
    hash3       = "27a20a400d7aa13737d230acf36a2170494c7da92e72552775d19562ba331fdc"

  strings:
    $s1 = "on fuck(){return \"OQr\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return " ascii
    $s2 = "function fuck(){return \"Ot\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){re" ascii
    $s3 = "(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){r" ascii
    $s4 = "\"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"SUi\";})(),(func" ascii
    $s5 = "(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"KVh\";})(),(function fuck(" ascii
    $s6 = "rn \"Vb\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"CCb\";})(),(fu" ascii
    $s7 = "uck(){return \"Fv\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"GJx" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}