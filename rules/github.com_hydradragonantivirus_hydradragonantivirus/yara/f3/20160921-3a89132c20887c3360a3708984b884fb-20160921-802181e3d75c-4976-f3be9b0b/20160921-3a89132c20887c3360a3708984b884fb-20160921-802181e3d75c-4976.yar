rule _20160921_3a89132c20887c3360a3708984b884fb_20160921_802181e3d75c_4976 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a89132c20887c3360a3708984b884fb.js, 20160921_802181e3d75c3e2d045cebba97849683.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9687ad9b2ded14e00c5b17393de82acd451266863fb217fc6647e1add112f2fd"
    hash2       = "ab42f16384f05ce6299f1ffd60f980af6ecf1fa2d23befc951797d1d52915400"

  strings:
    $s1 = " f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"V" ascii
    $s2 = " \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Vu\";})(),(fun" ascii
    $s3 = " f000(){return \"ZGq\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Zj" ascii
    $s4 = "eturn \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})()," ascii
    $s5 = "(function f000(){return \"Vu\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}