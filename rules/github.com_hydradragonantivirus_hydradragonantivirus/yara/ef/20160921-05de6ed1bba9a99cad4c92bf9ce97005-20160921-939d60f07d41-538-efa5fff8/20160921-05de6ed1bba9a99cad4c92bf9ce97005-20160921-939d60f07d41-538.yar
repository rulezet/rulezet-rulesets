rule _20160921_05de6ed1bba9a99cad4c92bf9ce97005_20160921_939d60f07d41_538 {
  meta:
    description = "datamaliciousorder - from files 20160921_05de6ed1bba9a99cad4c92bf9ce97005.js, 20160921_939d60f07d4171a5bae4c0b4ca33f3d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc9a1bb338cbe502eae2d8092d1b4369f9be8a107f4db340bf51a1640991e960"
    hash2       = "c23bfef986de7a073bbcd781aa45ad15287fb2c448d110b92a01e652f22ff335"

  strings:
    $s1  = "tion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return " ascii
    $s2  = "n \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"ZFe\";})(),(fu" ascii
    $s3  = "eturn \"BMj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})()" ascii
    $s4  = "){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"DYx\";" ascii
    $s5  = " f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"G" ascii
    $s6  = "turn \"Lp\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(" ascii
    $s7  = "n \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"NYh\";})(),(fun" ascii
    $s8  = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Qa\";})(),(function f000(" ascii
    $s9  = "ion f000(){return \"XTn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"OUx\";})(),(function f000(){return" ascii
    $s10 = "unction f000(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s11 = "rn \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Km\";})(),(fun" ascii
    $s12 = "00(){return \"NYh\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb" ascii
    $s13 = "ion f000(){return \"Vj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s14 = "urn \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Rh\";})(),(f" ascii
    $s15 = "{return \"Qj\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"QDg\";})" ascii
    $s16 = "nction f000(){return \"QDg\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"NBs\";})(),(function f000(){ret" ascii
    $s17 = "\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"WIj\";})(),(function " ascii
    $s18 = "turn \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Vj\";})(),(f" ascii
    $s19 = "f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"OM" ascii
    $s20 = ",(function f000(){return \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}