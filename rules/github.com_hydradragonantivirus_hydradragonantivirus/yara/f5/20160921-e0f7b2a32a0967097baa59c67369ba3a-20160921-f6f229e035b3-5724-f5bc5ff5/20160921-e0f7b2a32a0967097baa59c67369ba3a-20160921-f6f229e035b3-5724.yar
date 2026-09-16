rule _20160921_e0f7b2a32a0967097baa59c67369ba3a_20160921_f6f229e035b3_5724 {
  meta:
    description = "datamaliciousorder - from files 20160921_e0f7b2a32a0967097baa59c67369ba3a.js, 20160921_f6f229e035b34b52398f9d713af3e947.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d527617da74d553b6d56b37f7b101c14280b85e5e40e1f565fe396f8b97b29a2"
    hash2       = "dbd2ccfd17959ea084fe518e1748ca4f14e74a14593d7c157b17f4437f4336e3"

  strings:
    $s1 = "k(){return \"MOj\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Mw\";}" ascii
    $s2 = "ction fuck(){return \"Yk\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return " ascii
    $s3 = "rn \"Ar\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"MOj\";})(),(fu" ascii
    $s4 = "KVh\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Xw\";})(),(functio" ascii
    $s5 = ")(),(function fuck(){return \"Za\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Ik\";})(),(function fuck(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}