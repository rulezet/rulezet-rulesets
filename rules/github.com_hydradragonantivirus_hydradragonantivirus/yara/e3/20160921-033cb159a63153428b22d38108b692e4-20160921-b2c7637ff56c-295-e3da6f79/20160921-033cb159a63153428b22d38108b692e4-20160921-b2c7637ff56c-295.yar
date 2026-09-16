rule _20160921_033cb159a63153428b22d38108b692e4_20160921_b2c7637ff56c_295 {
  meta:
    description = "datamaliciousorder - from files 20160921_033cb159a63153428b22d38108b692e4.js, 20160921_b2c7637ff56cbf278f1a457ae1833df9.js, 20160921_ff1932b6e91481dd80ff6251296b57fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d370303fc83ddc3470e00cb54841641f9f338c2f025096e84d40782778041a8b"
    hash2       = "a19789bb6f28d27bc82c039f4db69fb5cc4c189a7a47cddfffcdc6eace37a408"
    hash3       = "07e5271d8517f89575dc2737fae5e8da89c7f2f25cd40c68e183d826da6b2bf0"

  strings:
    $s1  = "on f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return " ascii
    $s2  = "Rc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(),(functi" ascii
    $s3  = "ion f000(){return \"TKl\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return" ascii
    $s4  = "){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})" ascii
    $s5  = "Pu\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BQb\";})(),(functi" ascii
    $s6  = "eturn \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"XTn\";})()" ascii
    $s7  = "g\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(),(functio" ascii
    $s8  = "unction f000(){return \"ZFe\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){re" ascii
    $s9  = "turn \"ZFe\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})()," ascii
    $s10 = "tion f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Qa\";})(),(function f000(){return" ascii
    $s11 = "f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MD" ascii
    $s12 = "00(){return \"Nv\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";" ascii
    $s13 = "return \"Do\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Nv\";})()" ascii
    $s14 = "function f000(){return \"Qa\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(function f000(){ret" ascii
    $s15 = "function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){ret" ascii
    $s16 = "nction f000(){return \"Qa\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s17 = "tion f000(){return \"OUx\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Qz\";})(),(function f000(){return" ascii
    $s18 = "\"TKl\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s19 = "(function f000(){return \"KXg\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"RPt\";})(),(function f000(){" ascii
    $s20 = "unction f000(){return \"DYs\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"RPt\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}