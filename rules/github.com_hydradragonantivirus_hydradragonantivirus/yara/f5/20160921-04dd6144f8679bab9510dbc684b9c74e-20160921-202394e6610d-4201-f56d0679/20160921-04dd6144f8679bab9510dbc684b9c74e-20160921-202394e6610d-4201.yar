rule _20160921_04dd6144f8679bab9510dbc684b9c74e_20160921_202394e6610d_4201 {
  meta:
    description = "datamaliciousorder - from files 20160921_04dd6144f8679bab9510dbc684b9c74e.js, 20160921_202394e6610dfa0f27f737c781d5c579.js, 20160921_68e1fc90afca497654d8f771197c2097.js, 20160922_4dfe760897656c6a111dd28b33055e75.js, 20160922_ed715c18f1a8b288b3a2daf159dfdcd6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97824f5d282c20ba44b29b6dd0ffef72c3a4a7419c474527e64dfb49c4f0cb89"
    hash2       = "d10df61dcb3a781b5266597c0f1a9d52066cebbebf5196ad93fd81855575ed11"
    hash3       = "2dfe35f2d9bfd20a5e4771207c1627566795391c957d7b630cc669d3d8856ffd"
    hash4       = "76bf32cf7f7f6a161a3026c310b904328d9bce752e8955fb620779c62c11a6f5"
    hash5       = "d20943739c1e8a30074140436d0501b5156b43d83a6fd59a63cb1a5a8cb78432"

  strings:
    $s1 = "turn \"Nv\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s2 = "(),(function f000(){return \"Rh\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(" ascii
    $s3 = "urn \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Oe\";})(),(" ascii
    $s4 = "ction f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Go\";})(),(function f000(){return" ascii
    $s5 = " f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}