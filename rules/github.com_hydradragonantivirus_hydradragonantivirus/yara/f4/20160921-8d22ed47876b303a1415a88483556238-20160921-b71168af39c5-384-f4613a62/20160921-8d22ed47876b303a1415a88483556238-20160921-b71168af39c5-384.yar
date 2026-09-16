rule _20160921_8d22ed47876b303a1415a88483556238_20160921_b71168af39c5_384 {
  meta:
    description = "datamaliciousorder - from files 20160921_8d22ed47876b303a1415a88483556238.js, 20160921_b71168af39c5eec1d403d381eea7ffe1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "666a3f8cd9a533a20e260aad6bcb18265aad030f6f978c4cc3c9da557262f1ae"
    hash2       = "c8811edeb74999e8dd226f7fa9d7963ccfc998904ecb9474d036376253dc6fde"

  strings:
    $s1  = "f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Kw" ascii
    $s2  = " f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj" ascii
    $s3  = "n \"OUx\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Do\";})(),(func" ascii
    $s4  = "{return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})" ascii
    $s5  = "n \"GGn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"RPt\";})(),(fun" ascii
    $s6  = "nction f000(){return \"Do\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KDh\";})(),(function f000(){retu" ascii
    $s7  = "nction f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"ZGq\";})(),(function f000(){retu" ascii
    $s8  = "z\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Yi\";})(),(function" ascii
    $s9  = "nction f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){retu" ascii
    $s10 = "000(){return \"XTn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Yi" ascii
    $s11 = "tion f000(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return " ascii
    $s12 = "function f000(){return \"RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Yi\";})(),(function f000(){ret" ascii
    $s13 = "Kl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TRc\";})(),(functio" ascii
    $s14 = "tion f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"RPt\";})(),(function f000(){return" ascii
    $s15 = "on f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj\";})(),(function f000(){return " ascii
    $s16 = "tion f000(){return \"WIj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){return " ascii
    $s17 = "\"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Do\";})(),(func" ascii
    $s18 = "function f000(){return \"WIj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Do\";})(),(function f000(){re" ascii
    $s19 = "KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(function" ascii
    $s20 = " f000(){return \"Ot\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"K" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}