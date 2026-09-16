rule _20160921_3a89132c20887c3360a3708984b884fb_20160921_3b3df29e27c3_4979 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a89132c20887c3360a3708984b884fb.js, 20160921_3b3df29e27c35ab2e50a3446fa67bf66.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9687ad9b2ded14e00c5b17393de82acd451266863fb217fc6647e1add112f2fd"
    hash2       = "dd15d322a8169ff9edb922ead245c93109f14c5fa4f31811eb58601888323ad2"

  strings:
    $s1 = "on f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"" ascii
    $s2 = "{return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Vj\";})(" ascii
    $s3 = " f000(){return \"TKl\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do" ascii
    $s4 = "function f000(){return \"XTn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TRc\";})(),(function f000(){re" ascii
    $s5 = "ion f000(){return \"Vj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}