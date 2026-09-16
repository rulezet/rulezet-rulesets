rule _20160921_04dd6144f8679bab9510dbc684b9c74e_20160921_975c5c13ffec_642 {
  meta:
    description = "datamaliciousorder - from files 20160921_04dd6144f8679bab9510dbc684b9c74e.js, 20160921_975c5c13ffec0e2608898a142a2baed7.js, 20160921_f1cc02f488792b7161849f8d15549315.js, 20160922_4dfe760897656c6a111dd28b33055e75.js, 20160922_ed715c18f1a8b288b3a2daf159dfdcd6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97824f5d282c20ba44b29b6dd0ffef72c3a4a7419c474527e64dfb49c4f0cb89"
    hash2       = "4635f6ab0f307c878451c2e13b93f8c364364fd9dbd9b0a493d7990bc3eb3c17"
    hash3       = "a4438fd9b6e1eb385945338a0e8eaf272adfda2172cb3659bc36af2d1cc76ce5"
    hash4       = "76bf32cf7f7f6a161a3026c310b904328d9bce752e8955fb620779c62c11a6f5"
    hash5       = "d20943739c1e8a30074140436d0501b5156b43d83a6fd59a63cb1a5a8cb78432"

  strings:
    $s1  = "tion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return" ascii
    $s2  = "(),(function f000(){return \"Um\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"DIa\";})(),(function f000(" ascii
    $s3  = " \"Tn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(fun" ascii
    $s4  = "){return \"PTs\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZGq\";}" ascii
    $s5  = "n f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"" ascii
    $s6  = "MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"DYx\";})(),(funct" ascii
    $s7  = "turn \"SEo\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()," ascii
    $s8  = "urn \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"NBs\";})()," ascii
    $s9  = "000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Yv" ascii
    $s10 = "\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MDb\";})(),(function " ascii
    $s11 = ";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Yz\";})(),(function f00" ascii
    $s12 = "turn \"Vu\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"TKl\";})(),(f" ascii
    $s13 = "turn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Nx\";})()," ascii
    $s14 = "return \"ZFe\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(" ascii
    $s15 = "000(){return \"KDh\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn" ascii
    $s16 = "ction f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Tb\";})(),(function f000(){return" ascii
    $s17 = "n f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"S" ascii
    $s18 = " \"ZGq\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"WIj\";})(),(func" ascii
    $s19 = " \"SEo\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(func" ascii
    $s20 = "0(){return \"QDg\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Qz\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}