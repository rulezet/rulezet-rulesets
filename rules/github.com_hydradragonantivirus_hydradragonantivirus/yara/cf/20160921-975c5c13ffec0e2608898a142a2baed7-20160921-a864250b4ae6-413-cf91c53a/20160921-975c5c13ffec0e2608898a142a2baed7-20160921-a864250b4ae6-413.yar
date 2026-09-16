rule _20160921_975c5c13ffec0e2608898a142a2baed7_20160921_a864250b4ae6_413 {
  meta:
    description = "datamaliciousorder - from files 20160921_975c5c13ffec0e2608898a142a2baed7.js, 20160921_a864250b4ae6162ed0d7a2f3ed785d46.js, 20160921_f1cc02f488792b7161849f8d15549315.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4635f6ab0f307c878451c2e13b93f8c364364fd9dbd9b0a493d7990bc3eb3c17"
    hash2       = "f64f9f9fd1a5e4b096281bd9733f52c453683cc9032801264dd73f202b17964f"
    hash3       = "a4438fd9b6e1eb385945338a0e8eaf272adfda2172cb3659bc36af2d1cc76ce5"

  strings:
    $s1  = "eturn \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Lp\";})()," ascii
    $s2  = "n f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"K" ascii
    $s3  = "0(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";" ascii
    $s4  = "return \"Do\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"KZr\";})(),(function f000(){return \"MMz\";})()" ascii
    $s5  = "(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Sv\";})(" ascii
    $s6  = "Ij\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Wb\";})(),(function " ascii
    $s7  = "on f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(function f000(){return \"" ascii
    $s8  = "000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Zj" ascii
    $s9  = "Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function" ascii
    $s10 = "0(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"XTn\"" ascii
    $s11 = "000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Lp" ascii
    $s12 = "on f000(){return \"Qj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"" ascii
    $s13 = " \"OUx\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Yi\";})(),(func" ascii
    $s14 = "Pt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function" ascii
    $s15 = "ion f000(){return \"Qz\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"" ascii
    $s16 = "f000(){return \"Yi\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj" ascii
    $s17 = "t\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TRc\";})(),(function " ascii
    $s18 = " f000(){return \"GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"" ascii
    $s19 = "\"Yi\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(functio" ascii
    $s20 = "ction f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}