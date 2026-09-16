rule _20160921_3941d41b2f7cb84a9ce802558f71cf2e_20160921_b18e047e5b3f_342 {
  meta:
    description = "datamaliciousorder - from files 20160921_3941d41b2f7cb84a9ce802558f71cf2e.js, 20160921_b18e047e5b3fa2131425e272781d97b4.js, 20160921_c86a534fb694b7c269b48a9dc32f8a87.js, 20160921_d6e5226f779c21f4fc4b67aeddca2869.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af803579fff33b5e316911dc121155eb553434eec287816287bbd86b427b3f7f"
    hash2       = "033421645eb5cdfdccc02e470b5304f91fa62121d1e117f1aebca723440cec70"
    hash3       = "921432f56757fdaa414b8b2f729fdd46e41c954a0a96b706c646c1d5ab09e5cb"
    hash4       = "42ec93947d9a157ccd37a3c75c7a06b75fa756fee925b759536deb0993f07a5b"

  strings:
    $s1  = "n\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"XTn\";})(),(function " ascii
    $s2  = "{return \"Qz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})()," ascii
    $s3  = "{return \"WIj\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"RPt\";})(" ascii
    $s4  = "rn \"Yi\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s5  = "})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"ZGq\";})(),(function f00" ascii
    $s6  = "q\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Sv\";})(),(function " ascii
    $s7  = "nction f000(){return \"TKl\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"ZGq\";})(),(function f000(){retu" ascii
    $s8  = "n \"Qz\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Mu\";})(),(fun" ascii
    $s9  = "n \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(fun" ascii
    $s10 = "00(){return \"Qj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Zj\"" ascii
    $s11 = "function f000(){return \"Kw\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qz\";})(),(function f000(){retu" ascii
    $s12 = "n \"ZGq\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})(),(fu" ascii
    $s13 = "ction f000(){return \"Yi\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Zj\";})(),(function f000(){return" ascii
    $s14 = "unction f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Uo\";})(),(function f000(){retu" ascii
    $s15 = "tion f000(){return \"WIj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return " ascii
    $s16 = "f000(){return \"Lp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"XTn" ascii
    $s17 = "w\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})(),(function" ascii
    $s18 = "{return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Zj\";})()" ascii
    $s19 = "n f000(){return \"RPt\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"" ascii
    $s20 = "n f000(){return \"WIj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"R" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}