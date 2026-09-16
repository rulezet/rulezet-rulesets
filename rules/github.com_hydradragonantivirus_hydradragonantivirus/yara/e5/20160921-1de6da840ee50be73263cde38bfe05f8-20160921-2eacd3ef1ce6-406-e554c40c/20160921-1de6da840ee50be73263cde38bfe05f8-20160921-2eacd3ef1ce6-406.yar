rule _20160921_1de6da840ee50be73263cde38bfe05f8_20160921_2eacd3ef1ce6_406 {
  meta:
    description = "datamaliciousorder - from files 20160921_1de6da840ee50be73263cde38bfe05f8.js, 20160921_2eacd3ef1ce6866325342ce8cba80e38.js, 20160921_e985c90f8141417e484ad0056c9b809c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28c58fd3e89dda2f745d131d428bf5c447e7f5e2bdee82bb72c417d8a0be878a"
    hash2       = "128e4fae256d5c8ef6708fbd7f51b17e3da126d63b88361b0e92c9808a0c393f"
    hash3       = "513b80dc65238dcfcb80f0e8e4f456645bf345b2dde46805b001c07bc579d4c9"

  strings:
    $s1  = "nction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){retu" ascii
    $s2  = "})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qj\";})(),(function f000(" ascii
    $s3  = "){return \"Vj\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"OMd\";})" ascii
    $s4  = "0(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"NYh" ascii
    $s5  = "nction f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){retu" ascii
    $s6  = "unction f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Lp\";})(),(function f000(){retu" ascii
    $s7  = "\"Nv\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(func" ascii
    $s8  = "(function f000(){return \"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){r" ascii
    $s9  = "f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"ZIi" ascii
    $s10 = " f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz" ascii
    $s11 = "f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"DIa" ascii
    $s12 = "z\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function " ascii
    $s13 = "tion f000(){return \"Iq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"QDg\";})(),(function f000(){return" ascii
    $s14 = "0(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Yi\";" ascii
    $s15 = "ion f000(){return \"QDg\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return " ascii
    $s16 = " \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Do\";})(),(funct" ascii
    $s17 = " f000(){return \"WIj\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"BM" ascii
    $s18 = "ction f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){retur" ascii
    $s19 = "urn \"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"KZr\";})(),(f" ascii
    $s20 = " f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Yi" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}