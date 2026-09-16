rule _20160921_68e1fc90afca497654d8f771197c2097_20160921_975c5c13ffec_5341 {
  meta:
    description = "datamaliciousorder - from files 20160921_68e1fc90afca497654d8f771197c2097.js, 20160921_975c5c13ffec0e2608898a142a2baed7.js, 20160921_a864250b4ae6162ed0d7a2f3ed785d46.js, 20160921_f1cc02f488792b7161849f8d15549315.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2dfe35f2d9bfd20a5e4771207c1627566795391c957d7b630cc669d3d8856ffd"
    hash2       = "4635f6ab0f307c878451c2e13b93f8c364364fd9dbd9b0a493d7990bc3eb3c17"
    hash3       = "f64f9f9fd1a5e4b096281bd9733f52c453683cc9032801264dd73f202b17964f"
    hash4       = "a4438fd9b6e1eb385945338a0e8eaf272adfda2172cb3659bc36af2d1cc76ce5"

  strings:
    $s1 = "n f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"" ascii
    $s2 = "n\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Yi\";})(),(function f" ascii
    $s3 = "ion f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return " ascii
    $s4 = "eturn \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})()" ascii
    $s5 = "){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}