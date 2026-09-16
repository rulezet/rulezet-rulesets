rule _20160921_884f773b3c246c835029fc91499fb017_20160921_e63dc8126cee_5492 {
  meta:
    description = "datamaliciousorder - from files 20160921_884f773b3c246c835029fc91499fb017.js, 20160921_e63dc8126cee826e8d941c1665ea92b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4523d83a689974fc97f79b6c7c440d4b9f2a13825d1b664954798d786c1e2609"
    hash2       = "b87ae77185b5925bd9480daa9d4b74b2291cc670108bf85e0379579434ebff34"

  strings:
    $s1 = "(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ar\";})(),(function fuck(" ascii
    $s2 = "k(){return \"Np\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";}" ascii
    $s3 = "{return \"Mw\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Za\";})()" ascii
    $s4 = "(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"IOs\";})(),(function fuck(" ascii
    $s5 = "unction fuck(){return \"Mw\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}