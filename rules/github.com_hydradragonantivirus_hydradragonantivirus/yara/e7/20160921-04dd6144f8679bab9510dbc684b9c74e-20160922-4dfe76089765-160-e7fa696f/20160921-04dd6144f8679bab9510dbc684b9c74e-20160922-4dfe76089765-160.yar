rule _20160921_04dd6144f8679bab9510dbc684b9c74e_20160922_4dfe76089765_160 {
  meta:
    description = "datamaliciousorder - from files 20160921_04dd6144f8679bab9510dbc684b9c74e.js, 20160922_4dfe760897656c6a111dd28b33055e75.js, 20160922_ed715c18f1a8b288b3a2daf159dfdcd6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97824f5d282c20ba44b29b6dd0ffef72c3a4a7419c474527e64dfb49c4f0cb89"
    hash2       = "76bf32cf7f7f6a161a3026c310b904328d9bce752e8955fb620779c62c11a6f5"
    hash3       = "d20943739c1e8a30074140436d0501b5156b43d83a6fd59a63cb1a5a8cb78432"

  strings:
    $s1  = "Kl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Oe\";})(),(functio" ascii
    $s2  = "){return \"PTs\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Wh\";}" ascii
    $s3  = "on f000(){return \"OUx\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"" ascii
    $s4  = "tion f000(){return \"OUx\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})(),(function f000(){return" ascii
    $s5  = "(),(function f000(){return \"MDb\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"RLk\";})(),(function f000" ascii
    $s6  = "return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"YTp\";})" ascii
    $s7  = "ion f000(){return \"Tn\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"" ascii
    $s8  = "Qz\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(functio" ascii
    $s9  = "ction f000(){return \"ZGq\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"RVb\";})(),(function f000(){retu" ascii
    $s10 = "on f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return " ascii
    $s11 = "rn \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Yi\";})(),(fun" ascii
    $s12 = "unction f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){ret" ascii
    $s13 = " f000(){return \"Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc" ascii
    $s14 = "on f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"" ascii
    $s15 = "Gn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s16 = "),(function f000(){return \"QDg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Uo\";})(),(function f000(){" ascii
    $s17 = "Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"SGs\";})(),(functio" ascii
    $s18 = "f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Lp" ascii
    $s19 = "urn \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(f" ascii
    $s20 = "turn \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}