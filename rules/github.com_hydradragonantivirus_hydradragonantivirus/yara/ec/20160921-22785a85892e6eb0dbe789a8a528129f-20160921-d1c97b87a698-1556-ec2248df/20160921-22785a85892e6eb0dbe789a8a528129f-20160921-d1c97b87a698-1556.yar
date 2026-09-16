rule _20160921_22785a85892e6eb0dbe789a8a528129f_20160921_d1c97b87a698_1556 {
  meta:
    description = "datamaliciousorder - from files 20160921_22785a85892e6eb0dbe789a8a528129f.js, 20160921_d1c97b87a6985071e0e4edfb0e0dcc81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bd9f1cc39c45e7b6963f5eca04b26ef2eaf9c8005e5a0d5f12e868261ae58ca"
    hash2       = "b5d1f1d63107b329353fe8130c80608d28a9b1ed12f81c240129d04be6842bf0"

  strings:
    $s1  = "tion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"EZu\";})(),(function f000(){return" ascii
    $s2  = "on f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"" ascii
    $s3  = "ion f000(){return \"Vu\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Zj\";})(),(function f000(){return " ascii
    $s4  = "Ux\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Qz\";})(),(function " ascii
    $s5  = "unction f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){ret" ascii
    $s6  = "00(){return \"Vj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\"" ascii
    $s7  = "eturn \"GGn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"RPt\";})()" ascii
    $s8  = "rn \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(fun" ascii
    $s9  = "0(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Nv\";}" ascii
    $s10 = "00(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Oh" ascii
    $s11 = "on f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return " ascii
    $s12 = "rn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"DYx\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}