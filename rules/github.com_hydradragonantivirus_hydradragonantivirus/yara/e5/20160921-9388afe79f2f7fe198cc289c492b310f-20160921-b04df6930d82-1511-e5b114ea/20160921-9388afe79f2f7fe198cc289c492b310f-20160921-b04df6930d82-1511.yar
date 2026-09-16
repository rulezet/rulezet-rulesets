rule _20160921_9388afe79f2f7fe198cc289c492b310f_20160921_b04df6930d82_1511 {
  meta:
    description = "datamaliciousorder - from files 20160921_9388afe79f2f7fe198cc289c492b310f.js, 20160921_b04df6930d827daddc0cb4f32f5a0ac7.js, 20160921_d6071fc0b387420da4f4d56c9cc4f29c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd51f1b0a7122eb391698c985377ffff7f055696d2ab09fca71851b63308ba93"
    hash2       = "20f05e81e91c6d1996527f4c971330eb9446dbb6ad0d88c4d97a9739264f79ba"
    hash3       = "3582ec61c8d16a4dd7e6b8ba69c238b2abf1b60a1d05ebc8f672103586bdfd47"

  strings:
    $s1  = ";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"ZIi\";})(),(function f0" ascii
    $s2  = "f000(){return \"XTn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MM" ascii
    $s3  = "000(){return \"OUx\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Rh" ascii
    $s4  = ";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Oh\";})(),(function f00" ascii
    $s5  = ";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Sj\";})(),(function f00" ascii
    $s6  = "(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Mc\";" ascii
    $s7  = "{return \"Sj\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Ml\";})()" ascii
    $s8  = "0(){return \"KXg\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\"" ascii
    $s9  = "\"Vu\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";})(),(funct" ascii
    $s10 = "turn \"Iq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Oh\";})(),(f" ascii
    $s11 = "tion f000(){return \"BIj\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return" ascii
    $s12 = "MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Oh\";})(),(function" ascii
    $s13 = "{return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Sj\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}