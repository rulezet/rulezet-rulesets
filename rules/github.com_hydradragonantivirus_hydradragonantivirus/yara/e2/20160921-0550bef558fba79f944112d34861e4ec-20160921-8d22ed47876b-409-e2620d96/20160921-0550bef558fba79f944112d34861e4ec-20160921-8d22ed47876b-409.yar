rule _20160921_0550bef558fba79f944112d34861e4ec_20160921_8d22ed47876b_409 {
  meta:
    description = "datamaliciousorder - from files 20160921_0550bef558fba79f944112d34861e4ec.js, 20160921_8d22ed47876b303a1415a88483556238.js, 20160921_e432cba10cde369693d6b125dda112c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cc46901b4b691df366f68f1812df531215964f5150686b06997f1f49b536a1c"
    hash2       = "666a3f8cd9a533a20e260aad6bcb18265aad030f6f978c4cc3c9da557262f1ae"
    hash3       = "0f0aa2d80d649fb44a67c6ec77b95eb26709057f543ca215edf15a9bcc4bae4b"

  strings:
    $s1  = "j\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function " ascii
    $s2  = " f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Y" ascii
    $s3  = " \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(func" ascii
    $s4  = "function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})(),(function f000(){ret" ascii
    $s5  = "eturn \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(" ascii
    $s6  = "nction f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){retu" ascii
    $s7  = "n \"Lp\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TKl\";})(),(fun" ascii
    $s8  = "\"Qj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(functi" ascii
    $s9  = "Pt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(functio" ascii
    $s10 = "0(){return \"XTn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";" ascii
    $s11 = "(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";}" ascii
    $s12 = "(function f000(){return \"RPt\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){" ascii
    $s13 = "0(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";}" ascii
    $s14 = "urn \"Sj\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"WIj\";})(),(fu" ascii
    $s15 = "rn \"WIj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(fu" ascii
    $s16 = "unction f000(){return \"Kw\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"XTn\";})(),(function f000(){retu" ascii
    $s17 = "00(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Do" ascii
    $s18 = "0(){return \"Lp\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})" ascii
    $s19 = "000(){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";" ascii
    $s20 = "turn \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qj\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}