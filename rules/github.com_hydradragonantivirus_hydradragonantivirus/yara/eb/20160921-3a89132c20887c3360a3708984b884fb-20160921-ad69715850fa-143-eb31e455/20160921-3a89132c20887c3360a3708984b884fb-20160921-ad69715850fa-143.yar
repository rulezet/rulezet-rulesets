rule _20160921_3a89132c20887c3360a3708984b884fb_20160921_ad69715850fa_143 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a89132c20887c3360a3708984b884fb.js, 20160921_ad69715850fae108d9a16055efb4f51c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9687ad9b2ded14e00c5b17393de82acd451266863fb217fc6647e1add112f2fd"
    hash2       = "76ed8c5c3ace4ce119f1561d5d61ca2e454da79e9156a8397e72d6eed3a22d74"

  strings:
    $s1  = "n \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"RLk\";})(),(fun" ascii
    $s2  = "eturn \"Br\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Br\";})(),(" ascii
    $s3  = "unction f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"TKp\";})(),(function f000(){ret" ascii
    $s4  = "ction f000(){return \"Br\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Br\";})(),(function f000(){return" ascii
    $s5  = "urn \"Sv\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(f" ascii
    $s6  = "ion f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"OMd\";})(),(function f000(){return " ascii
    $s7  = "i\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function" ascii
    $s8  = "000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Wb\"" ascii
    $s9  = "return \"TKp\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(" ascii
    $s10 = "\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Qj\";})(),(function f" ascii
    $s11 = "n \"KDh\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s12 = "Qb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"NBs\";})(),(function" ascii
    $s13 = "n f000(){return \"UEg\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"G" ascii
    $s14 = "Gn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"MMz\";})(),(functio" ascii
    $s15 = "(){return \"Br\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Sv\";}" ascii
    $s16 = "nction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){retu" ascii
    $s17 = "\"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"ZGq\";})(),(func" ascii
    $s18 = "ion f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"KDh\";})(),(function f000(){return" ascii
    $s19 = "urn \"Br\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Uo\";})(),(fun" ascii
    $s20 = "tion f000(){return \"Mt\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Oe\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}