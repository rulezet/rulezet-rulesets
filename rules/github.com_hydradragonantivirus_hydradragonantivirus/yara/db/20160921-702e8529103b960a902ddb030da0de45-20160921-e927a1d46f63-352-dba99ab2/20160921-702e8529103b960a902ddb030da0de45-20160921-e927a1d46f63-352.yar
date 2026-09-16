rule _20160921_702e8529103b960a902ddb030da0de45_20160921_e927a1d46f63_352 {
  meta:
    description = "datamaliciousorder - from files 20160921_702e8529103b960a902ddb030da0de45.js, 20160921_e927a1d46f63fcc6ccb740b1d71293f3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf8ba9fdbe4ef225cb892f7294538710b1dd7e8bc4e280897680c51e03816d1c"
    hash2       = "a681cf04685052da0d288a0246e49880f34a91dc46ff378f7cf1859ae526c1ef"

  strings:
    $s1  = "{return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})" ascii
    $s2  = "unction f000(){return \"SGs\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Km\";})(),(function f000(){ret" ascii
    $s3  = ")(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj\";})(),(function f000" ascii
    $s4  = "rn \"WIj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"XTn\";})(),(fu" ascii
    $s5  = " \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Iq\";})(),(funct" ascii
    $s6  = "turn \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})()," ascii
    $s7  = "0(){return \"Sv\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TRc\";" ascii
    $s8  = "Dg\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Tn\";})(),(function" ascii
    $s9  = "{return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Yi\";})(" ascii
    $s10 = "000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Mt" ascii
    $s11 = "function f000(){return \"GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){r" ascii
    $s12 = "n \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(fun" ascii
    $s13 = "t\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(function " ascii
    $s14 = "u\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(functio" ascii
    $s15 = "ction f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TKl\";})(),(function f000(){retur" ascii
    $s16 = "\"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Do\";})(),(func" ascii
    $s17 = "ion f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return " ascii
    $s18 = "0(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qj\";" ascii
    $s19 = "turn \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Sj\";})(),(fu" ascii
    $s20 = "\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"XTn\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}