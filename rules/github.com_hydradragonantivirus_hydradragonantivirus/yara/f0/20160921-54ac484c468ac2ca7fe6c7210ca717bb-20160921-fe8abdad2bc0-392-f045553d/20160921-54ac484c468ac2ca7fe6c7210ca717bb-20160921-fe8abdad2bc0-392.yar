rule _20160921_54ac484c468ac2ca7fe6c7210ca717bb_20160921_fe8abdad2bc0_392 {
  meta:
    description = "datamaliciousorder - from files 20160921_54ac484c468ac2ca7fe6c7210ca717bb.js, 20160921_fe8abdad2bc00d1378e2964402e33217.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b883334540a4216b3582d1f2fa0a27f21b9c64a87944c8e58d9fab0f609eef3"
    hash2       = "39d0496129988da40dbbddcff6610a39be1f05ddd7f48a13058b749810c8400d"

  strings:
    $s1  = "000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"ZGq" ascii
    $s2  = "function f000(){return \"Mu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"ZGq\";})(),(function f000(){re" ascii
    $s3  = "unction f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(function f000(){retur" ascii
    $s4  = "){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Kw\";})" ascii
    $s5  = "t\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function" ascii
    $s6  = "n \"GGn\";})(),(function f000(){return \"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"XTn\";})(),(fu" ascii
    $s7  = "0(){return \"Kw\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"TRc\";" ascii
    $s8  = "{return \"Qj\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})(" ascii
    $s9  = ",(function f000(){return \"XTn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){" ascii
    $s10 = "\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"ZGq\";})(),(function f" ascii
    $s11 = "turn \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"ZGq\";})(),(f" ascii
    $s12 = "000(){return \"Sj\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc" ascii
    $s13 = "f000(){return \"Qz\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Do" ascii
    $s14 = "unction f000(){return \"Qz\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj\";})(),(function f000(){retur" ascii
    $s15 = "rn \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(f" ascii
    $s16 = "n \"Kw\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(fun" ascii
    $s17 = "00(){return \"GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Yi\"" ascii
    $s18 = " \"Qj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(func" ascii
    $s19 = "(){return \"KXg\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"ZGq\"" ascii
    $s20 = "00(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZGq" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}