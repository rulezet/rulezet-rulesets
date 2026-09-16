rule _20160921_6ed03f6116d83dcb603f8d7a421669a9_20160921_95270bbacde4_288 {
  meta:
    description = "datamaliciousorder - from files 20160921_6ed03f6116d83dcb603f8d7a421669a9.js, 20160921_95270bbacde4afcb3c799d7a0643809d.js, 20160921_b15ce64784b080eff109e1bd1b00ebf6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f10930e3c0bd956023b78dabf743464a690cb292b06d107d010614acff421c1"
    hash2       = "6cab57b5e35c3714b482592a77f0edbdc9fedb8c6e508d57b8cf63dfd719f5db"
    hash3       = "e78e24f62fb93be4551c02ce2a2a27421a39d4a9d5c77d37c7518adf9e53ce65"

  strings:
    $s1  = "rn \"Yi\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(func" ascii
    $s2  = "turn \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"TRc\";})()," ascii
    $s3  = "{return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Kw\";})()" ascii
    $s4  = " \"KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(fun" ascii
    $s5  = "rn \"KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(fu" ascii
    $s6  = "unction f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){ret" ascii
    $s7  = "ction f000(){return \"RPt\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Yi\";})(),(function f000(){return" ascii
    $s8  = "urn \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qa\";})(),(" ascii
    $s9  = "turn \"Uo\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"TRc\";})(),(f" ascii
    $s10 = "ction f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){retu" ascii
    $s11 = "000(){return \"ZFe\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj" ascii
    $s12 = "tion f000(){return \"ZFe\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return " ascii
    $s13 = "000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do" ascii
    $s14 = "function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){re" ascii
    $s15 = "function f000(){return \"Lp\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Iq\";})(),(function f000(){ret" ascii
    $s16 = "){return \"Qa\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TRc\";}" ascii
    $s17 = "eturn \"XTn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})()," ascii
    $s18 = "f000(){return \"QDg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"NB" ascii
    $s19 = "ion f000(){return \"KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"KXg\";})(),(function f000(){return " ascii
    $s20 = " f000(){return \"ZFe\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}