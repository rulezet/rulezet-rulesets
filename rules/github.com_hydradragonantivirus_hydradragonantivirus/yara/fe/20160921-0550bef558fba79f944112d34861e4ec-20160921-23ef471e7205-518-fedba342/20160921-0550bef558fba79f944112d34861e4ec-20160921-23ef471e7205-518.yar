rule _20160921_0550bef558fba79f944112d34861e4ec_20160921_23ef471e7205_518 {
  meta:
    description = "datamaliciousorder - from files 20160921_0550bef558fba79f944112d34861e4ec.js, 20160921_23ef471e720525eb3dff80c2296d1a60.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cc46901b4b691df366f68f1812df531215964f5150686b06997f1f49b536a1c"
    hash2       = "b0945c221a3a5ff2958847eac00c479ff3a9b1c8dd949684148aca0eeaf3afeb"

  strings:
    $s1  = "nction f000(){return \"Qz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"RLk\";})(),(function f000(){retu" ascii
    $s2  = "(function f000(){return \"MDb\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Iq\";})(),(function f000(){re" ascii
    $s3  = "function f000(){return \"ZFe\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GGn\";})(),(function f000(){r" ascii
    $s4  = "on f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"" ascii
    $s5  = "000(){return \"TKl\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"DY" ascii
    $s6  = "(){return \"Wy\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"UEg\";" ascii
    $s7  = "ion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DAp\";})(),(function f000(){return " ascii
    $s8  = "){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qj\";}" ascii
    $s9  = ",(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"ZGq\";})(),(function f000()" ascii
    $s10 = "),(function f000(){return \"DYs\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Rh\";})(),(function f000()" ascii
    $s11 = "Yi\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"PTs\";})(),(functi" ascii
    $s12 = ";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"SEo\";})(),(function f0" ascii
    $s13 = "ction f000(){return \"Qj\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s14 = "(function f000(){return \"TKp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"WIj\";})(),(function f000(){r" ascii
    $s15 = "ction f000(){return \"RPt\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s16 = "{return \"NYh\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})" ascii
    $s17 = "q\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vj\";})(),(function " ascii
    $s18 = "eturn \"Kw\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})()" ascii
    $s19 = "n \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"QDg\";})(),(fun" ascii
    $s20 = "on f000(){return \"Oh\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}