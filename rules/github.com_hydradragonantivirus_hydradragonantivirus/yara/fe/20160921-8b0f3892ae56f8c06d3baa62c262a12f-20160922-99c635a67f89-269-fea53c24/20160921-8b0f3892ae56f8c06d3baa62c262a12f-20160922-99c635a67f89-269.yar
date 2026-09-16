rule _20160921_8b0f3892ae56f8c06d3baa62c262a12f_20160922_99c635a67f89_269 {
  meta:
    description = "datamaliciousorder - from files 20160921_8b0f3892ae56f8c06d3baa62c262a12f.js, 20160922_99c635a67f8963210ce99c7a8cf9cd6c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96514db18a22f5e5bde10feb1f6b426e5772d0f7e76f227e8d49a7a00bfb01b7"
    hash2       = "c5b5cdc3be24f457939814321b7f3397a8f4d2370b1e57cdae1f3f10537e562c"

  strings:
    $s1  = "000(){return \"QDg\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Rh" ascii
    $s2  = "\"GGn\";})(),(function f000(){return \"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qz\";})(),(funct" ascii
    $s3  = "unction f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){ret" ascii
    $s4  = "rn \"Ot\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"KXg\";})(),(f" ascii
    $s5  = "Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Oh\";})(),(function" ascii
    $s6  = "ction f000(){return \"Iq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return" ascii
    $s7  = "000(){return \"WIj\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"KXg" ascii
    $s8  = "000(){return \"Yi\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\"" ascii
    $s9  = ";})(),(function f000(){return \"Do\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function f00" ascii
    $s10 = "00(){return \"GGn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Qz\"" ascii
    $s11 = "n f000(){return \"KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"T" ascii
    $s12 = ",(function f000(){return \"Qa\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){r" ascii
    $s13 = "turn \"ZFe\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";})(),(" ascii
    $s14 = ")(),(function f000(){return \"Ot\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"BMj\";})(),(function f000(" ascii
    $s15 = "0(){return \"ZFe\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\"" ascii
    $s16 = "ction f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"RPt\";})(),(function f000(){retu" ascii
    $s17 = "})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"KXg\";})(),(function f00" ascii
    $s18 = "\"MKa\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})()];" fullword ascii
    $s19 = " f000(){return \"Qa\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Z" ascii
    $s20 = "KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TRc\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}