rule _20160921_882f77897bba85afdc56810c29ef4cbb_20160921_9dad243650b7_5488 {
  meta:
    description = "datamaliciousorder - from files 20160921_882f77897bba85afdc56810c29ef4cbb.js, 20160921_9dad243650b7872772e7037b467b5a2e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e1a86c6dc71a5b10659658c07a01bb1541887750ecf88ab56997c7dbc2d180c"
    hash2       = "0d6dd5e22f8f66e5240683d3b57744793a88315a385138ff11409b0c03a9c448"

  strings:
    $s1 = "RLk\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(functi" ascii
    $s2 = "(){return \"BIj\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Wy\";})" ascii
    $s3 = ";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})(),(function f0" ascii
    $s4 = "unction f000(){return \"Sj0\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){re" ascii
    $s5 = ";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Yv\";})(),(function f0" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}