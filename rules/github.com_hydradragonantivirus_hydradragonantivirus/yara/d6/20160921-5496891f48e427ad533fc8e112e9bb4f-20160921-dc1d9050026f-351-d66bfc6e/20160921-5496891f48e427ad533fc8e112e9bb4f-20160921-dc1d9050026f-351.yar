rule _20160921_5496891f48e427ad533fc8e112e9bb4f_20160921_dc1d9050026f_351 {
  meta:
    description = "datamaliciousorder - from files 20160921_5496891f48e427ad533fc8e112e9bb4f.js, 20160921_dc1d9050026f8e96fefca2306b0b5aba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb85e1d59ed8f9cee344ab5ab95f651cb8fb1ee7ec35d0a88f8f41279a3d17a6"
    hash2       = "c6189a2d5bf1254f55c8d7ad46101d9c32dc62eda1d03b19dddb22f049f8965d"

  strings:
    $s1  = "){return \"XTn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})" ascii
    $s2  = "tion f000(){return \"ZGq\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Do\";})(),(function f000(){return " ascii
    $s3  = "w\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(function " ascii
    $s4  = "000(){return \"Do\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\"" ascii
    $s5  = "unction f000(){return \"Qj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){retu" ascii
    $s6  = "function f000(){return \"Lp\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){re" ascii
    $s7  = "RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(functio" ascii
    $s8  = "ion f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return" ascii
    $s9  = "(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TKl\";}" ascii
    $s10 = "(function f000(){return \"Nx\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){r" ascii
    $s11 = ")(),(function f000(){return \"Yi\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"RPt\";})(),(function f000" ascii
    $s12 = "{return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"QDg\";})" ascii
    $s13 = "rn \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TRc\";})(),(fu" ascii
    $s14 = "turn \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})()," ascii
    $s15 = "urn \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Lp\";})(),(fu" ascii
    $s16 = " \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Do\";})(),(func" ascii
    $s17 = "0(){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";})" ascii
    $s18 = "})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Do\";})(),(function f00" ascii
    $s19 = "tion f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"BMj\";})(),(function f000(){retur" ascii
    $s20 = "rn \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}