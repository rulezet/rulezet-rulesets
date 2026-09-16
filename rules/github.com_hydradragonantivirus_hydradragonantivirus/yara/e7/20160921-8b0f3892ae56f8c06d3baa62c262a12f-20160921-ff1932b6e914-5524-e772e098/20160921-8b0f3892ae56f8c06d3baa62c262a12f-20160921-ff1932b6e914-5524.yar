rule _20160921_8b0f3892ae56f8c06d3baa62c262a12f_20160921_ff1932b6e914_5524 {
  meta:
    description = "datamaliciousorder - from files 20160921_8b0f3892ae56f8c06d3baa62c262a12f.js, 20160921_ff1932b6e91481dd80ff6251296b57fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96514db18a22f5e5bde10feb1f6b426e5772d0f7e76f227e8d49a7a00bfb01b7"
    hash2       = "07e5271d8517f89575dc2737fae5e8da89c7f2f25cd40c68e183d826da6b2bf0"

  strings:
    $s1 = "000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Sq" ascii
    $s2 = "00(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"UEg" ascii
    $s3 = " f000(){return \"Mc\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZG" ascii
    $s4 = " \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s5 = " \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}