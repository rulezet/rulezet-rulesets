rule _20160921_1de6da840ee50be73263cde38bfe05f8_20160921_2eacd3ef1ce6_259 {
  meta:
    description = "datamaliciousorder - from files 20160921_1de6da840ee50be73263cde38bfe05f8.js, 20160921_2eacd3ef1ce6866325342ce8cba80e38.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28c58fd3e89dda2f745d131d428bf5c447e7f5e2bdee82bb72c417d8a0be878a"
    hash2       = "128e4fae256d5c8ef6708fbd7f51b17e3da126d63b88361b0e92c9808a0c393f"

  strings:
    $s1  = "on f000(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return " ascii
    $s2  = "unction f000(){return \"OUx\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"UEg\";})(),(function f000(){re" ascii
    $s3  = "Sj\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"WIj\";})(),(function" ascii
    $s4  = "tion f000(){return \"Qj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return" ascii
    $s5  = "0(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";" ascii
    $s6  = "turn \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qz\";})(),(" ascii
    $s7  = " f000(){return \"WIj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"G" ascii
    $s8  = "(function f000(){return \"KDh\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Iq\";})(),(function f000(){re" ascii
    $s9  = "\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"MBb\";})(),(function " ascii
    $s10 = "Ux\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Do\";})(),(function" ascii
    $s11 = "\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qj\";})(),(function f0" ascii
    $s12 = "turn \"Lp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(" ascii
    $s13 = "n f000(){return \"ZGq\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"T" ascii
    $s14 = "Pt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(function" ascii
    $s15 = "tion f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return" ascii
    $s16 = "ction f000(){return \"Kw\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Yi\";})(),(function f000(){return " ascii
    $s17 = "urn \"Do\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"DIa\";})(),(fu" ascii
    $s18 = "rn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"TKp\";})(),(f" ascii
    $s19 = " \"Kw\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"KXg\";})(),(funct" ascii
    $s20 = "nction f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})()];" fullword ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}