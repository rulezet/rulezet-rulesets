rule _20160921_099ae50c92fa9b72abe88204de915580_20160921_0f4dee7115fe_1652 {
  meta:
    description = "datamaliciousorder - from files 20160921_099ae50c92fa9b72abe88204de915580.js, 20160921_0f4dee7115fed314f330d52696c0d1d1.js, 20160921_87978dcbc3a23f5dbd5fc73bee04f432.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "344e6822e369c3beb064ffee655d0ce0db901d1bada577cd8f338fc2aec06cb8"
    hash2       = "dec7336f5db71057e4227c26b20731cd69ad29c7628e161fff2f7964754477b1"
    hash3       = "a6d96c94cf7f327ade629dec6f41b2fcfa7f7accfa8da780df3fea48273270dd"

  strings:
    $s1  = "{return \"YQt\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"CCb\";})" ascii
    $s2  = " fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"N" ascii
    $s3  = ")(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Ar\";})(),(function fuck(" ascii
    $s4  = "Pz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"MOj\";})(),(functio" ascii
    $s5  = ")(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"MBg\";})(),(function fuck" ascii
    $s6  = "tion fuck(){return \"SUi\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return" ascii
    $s7  = "nction fuck(){return \"GNm\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){retu" ascii
    $s8  = "tion fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return " ascii
    $s9  = "unction fuck(){return \"IRn\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){ret" ascii
    $s10 = "),(function fuck(){return \"LGo\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(" ascii
    $s11 = "urn \"Qh\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Cd\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}