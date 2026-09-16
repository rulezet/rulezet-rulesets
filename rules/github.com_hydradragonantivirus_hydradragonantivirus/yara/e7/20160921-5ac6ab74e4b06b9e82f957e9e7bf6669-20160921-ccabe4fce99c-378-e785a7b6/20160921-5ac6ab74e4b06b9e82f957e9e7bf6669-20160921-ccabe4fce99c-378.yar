rule _20160921_5ac6ab74e4b06b9e82f957e9e7bf6669_20160921_ccabe4fce99c_378 {
  meta:
    description = "datamaliciousorder - from files 20160921_5ac6ab74e4b06b9e82f957e9e7bf6669.js, 20160921_ccabe4fce99c1ebb627aa374a501f33c.js, 20160921_d4f0c091f748680e400a49909c223265.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50225d12c51a2decb97015971f8ce72487a24a69e64ec1d12fd7f720f2320cf3"
    hash2       = "449fe576ee25f77acba5442d771e770819941d7dbf354b5123ca5211ef743189"
    hash3       = "1bfdf43dd38b68a1577a28fa30f6ebe7fbbcc8d9fe32db4ebe1b162eaac6ba98"

  strings:
    $s1  = "on f000(){return \"Qj\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"K" ascii
    $s2  = "return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Zj\";})()," ascii
    $s3  = "function f000(){return \"OUx\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"XTn\";})(),(function f000(){r" ascii
    $s4  = "00(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Lp\"" ascii
    $s5  = "unction f000(){return \"OUx\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"XTn\";})(),(function f000(){ret" ascii
    $s6  = "){return \"XTn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})" ascii
    $s7  = "Gn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(functio" ascii
    $s8  = "nction f000(){return \"Do\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s9  = "n f000(){return \"Ot\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"" ascii
    $s10 = "turn \"WIj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(" ascii
    $s11 = "){return \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";}" ascii
    $s12 = "rn \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"XTn\";})(),(" ascii
    $s13 = "rn \"OUx\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Do\";})(),(fun" ascii
    $s14 = ")(),(function f000(){return \"XTn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Lp\";})(),(function f000(" ascii
    $s15 = "rn \"Iq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Sv\";})(),(fu" ascii
    $s16 = "ction f000(){return \"WIj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){return" ascii
    $s17 = "unction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){retu" ascii
    $s18 = "(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Lp\";" ascii
    $s19 = "nction f000(){return \"Qz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"RPt\";})(),(function f000(){retur" ascii
    $s20 = "000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TK" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}