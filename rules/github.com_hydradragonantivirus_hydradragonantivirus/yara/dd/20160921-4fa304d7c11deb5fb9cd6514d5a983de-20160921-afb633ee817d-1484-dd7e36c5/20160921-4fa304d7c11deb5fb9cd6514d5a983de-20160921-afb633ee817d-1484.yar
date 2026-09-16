rule _20160921_4fa304d7c11deb5fb9cd6514d5a983de_20160921_afb633ee817d_1484 {
  meta:
    description = "datamaliciousorder - from files 20160921_4fa304d7c11deb5fb9cd6514d5a983de.js, 20160921_afb633ee817d9b15b91ed82a059939fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cef5a1e67f57d9f24065ff0145644e0185df6abc29113310c6782b30e0a9236b"
    hash2       = "7a4e330bd3ec71aa3dc8fd3d5b2fa656b04d49cb5ee4e5478a50a6336c5bf9e5"

  strings:
    $s1  = "{return \"Ot\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"MOj\";})" ascii
    $s2  = "(function fuck(){return \"Jh\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){re" ascii
    $s3  = "function fuck(){return \"MBg\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){re" ascii
    $s4  = "nction fuck(){return \"Vb\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return" ascii
    $s5  = "fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Ot" ascii
    $s6  = "unction fuck(){return \"DRx\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){ret" ascii
    $s7  = "ck(){return \"DRx\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Vb\"" ascii
    $s8  = "k(){return \"Jo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"MOj\"" ascii
    $s9  = "){return \"ZVi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";}" ascii
    $s10 = "n \"OQr\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Np\";})(),(fun" ascii
    $s11 = "v\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"GJx\";})(),(functio" ascii
    $s12 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){retur" ascii
    $s13 = "DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"KVh\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}