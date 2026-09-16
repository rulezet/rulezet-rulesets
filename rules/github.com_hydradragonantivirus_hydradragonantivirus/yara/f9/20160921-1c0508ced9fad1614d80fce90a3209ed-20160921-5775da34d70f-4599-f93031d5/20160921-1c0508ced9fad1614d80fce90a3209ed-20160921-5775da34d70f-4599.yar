rule _20160921_1c0508ced9fad1614d80fce90a3209ed_20160921_5775da34d70f_4599 {
  meta:
    description = "datamaliciousorder - from files 20160921_1c0508ced9fad1614d80fce90a3209ed.js, 20160921_5775da34d70f97a2d7aa3296f909af35.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e27406e32c891781b5403c718c4f32d67f6580cf6f952a30d0c6452ab9775a4c"
    hash2       = "270e1d840937d10ac3eb1fdd04f0fbbbfd31a88a2f316c94c5167a23a2940644"

  strings:
    $s1 = "unction f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"UEg\";})(),(function f000(){re" ascii
    $s2 = "\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(function" ascii
    $s3 = "f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"G" ascii
    $s4 = "0(){return \"GGn\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\"" ascii
    $s5 = "turn \"Kw\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TKl\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}