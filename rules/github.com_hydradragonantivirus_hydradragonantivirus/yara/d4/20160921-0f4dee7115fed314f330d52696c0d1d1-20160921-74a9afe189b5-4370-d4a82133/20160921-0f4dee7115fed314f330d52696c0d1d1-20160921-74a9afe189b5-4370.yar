rule _20160921_0f4dee7115fed314f330d52696c0d1d1_20160921_74a9afe189b5_4370 {
  meta:
    description = "datamaliciousorder - from files 20160921_0f4dee7115fed314f330d52696c0d1d1.js, 20160921_74a9afe189b59f0b8148a7f92f42b125.js, 20160921_87978dcbc3a23f5dbd5fc73bee04f432.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dec7336f5db71057e4227c26b20731cd69ad29c7628e161fff2f7964754477b1"
    hash2       = "5ce6bfd72ee0a8f8259b2cfbaa6f5b49ec72ab64b03caf4bd2a4f733ef96925b"
    hash3       = "a6d96c94cf7f327ade629dec6f41b2fcfa7f7accfa8da780df3fea48273270dd"

  strings:
    $s1 = "MUs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(funct" ascii
    $s2 = "),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"AUx\";})(),(function fuck()" ascii
    $s3 = " \"Zy\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(func" ascii
    $s4 = "on fuck(){return \"Hs\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"N" ascii
    $s5 = "k(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IPu\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}