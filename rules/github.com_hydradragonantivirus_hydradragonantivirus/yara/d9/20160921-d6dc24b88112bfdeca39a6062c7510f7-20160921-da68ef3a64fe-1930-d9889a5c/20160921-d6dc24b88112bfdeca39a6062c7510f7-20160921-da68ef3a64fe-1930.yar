rule _20160921_d6dc24b88112bfdeca39a6062c7510f7_20160921_da68ef3a64fe_1930 {
  meta:
    description = "datamaliciousorder - from files 20160921_d6dc24b88112bfdeca39a6062c7510f7.js, 20160921_da68ef3a64fe9761a5f4505bcaef8f82.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b22daaadbd25f5bd920609cbc37e7ea10c4cd99c069220697c4c5db594cffee2"
    hash2       = "cecd93896e2d90bed54f31f9e387b5dcec7c277d5e455e561112b07c63d26ed5"

  strings:
    $s1  = "on f000(){return \"Oh\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"W" ascii
    $s2  = "unction f000(){return \"DNa\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Qa\";})(),(function f000(){ret" ascii
    $s3  = "\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"TRc\";})(),(function " ascii
    $s4  = "000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TK" ascii
    $s5  = " f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"" ascii
    $s6  = "){return \"BQb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"BMj\";}" ascii
    $s7  = "n \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s8  = "{return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})" ascii
    $s9  = "Qa\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(functio" ascii
    $s10 = "return \"WIj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}