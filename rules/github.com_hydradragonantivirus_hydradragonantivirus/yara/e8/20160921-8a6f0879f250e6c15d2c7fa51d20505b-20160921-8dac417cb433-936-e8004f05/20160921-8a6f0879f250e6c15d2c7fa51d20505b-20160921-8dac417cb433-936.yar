rule _20160921_8a6f0879f250e6c15d2c7fa51d20505b_20160921_8dac417cb433_936 {
  meta:
    description = "datamaliciousorder - from files 20160921_8a6f0879f250e6c15d2c7fa51d20505b.js, 20160921_8dac417cb4331fdefcd724e5c4563731.js, 20160921_c6163df7a6dda28826544197fc8ddc4f.js, 20160922_99c635a67f8963210ce99c7a8cf9cd6c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "221e50c91cd5c3d541d89b6c9999d61bacb186433ba85ae94088851587c25391"
    hash2       = "4ab6c9959d63ff05f6b1074253866e4ba4ca6148b9d820313ac79da48c63d90e"
    hash3       = "c0d0b12b3c6fc559a577159775ce104e897b9b5c0422b945c7c097dd53710fe8"
    hash4       = "c5b5cdc3be24f457939814321b7f3397a8f4d2370b1e57cdae1f3f10537e562c"

  strings:
    $s1  = "n\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Tn\";})(),(function f" ascii
    $s2  = "turn \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})()" ascii
    $s3  = "\"Wh\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TKl\";})(),(funct" ascii
    $s4  = "turn \"GGn\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Do\";})()," ascii
    $s5  = "eturn \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"DIa\";})(" ascii
    $s6  = "{return \"QDg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TKl\";}" ascii
    $s7  = "\"Do\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"ZFe\";})(),(func" ascii
    $s8  = " \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qa\";})(),(fun" ascii
    $s9  = " f000(){return \"Wy\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn" ascii
    $s10 = "){return \"Yi\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(" ascii
    $s11 = "\"ZFe\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s12 = "Do\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(functi" ascii
    $s13 = ";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"DIa\";})(),(function f0" ascii
    $s14 = "(){return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";" ascii
    $s15 = "nction f000(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Kw\";})(),(function f000(){retur" ascii
    $s16 = "Yx\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tn\";})(),(functio" ascii
    $s17 = "f000(){return \"QDg\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"D" ascii
    $s18 = "ction f000(){return \"MJq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Tn\";})(),(function f000(){retur" ascii
    $s19 = "0(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"NBs" ascii
    $s20 = "ion f000(){return \"OUx\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"XTn\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}