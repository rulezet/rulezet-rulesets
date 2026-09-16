rule _20160921_975c5c13ffec0e2608898a142a2baed7_20160921_dd666c66b3f1_5571 {
  meta:
    description = "datamaliciousorder - from files 20160921_975c5c13ffec0e2608898a142a2baed7.js, 20160921_dd666c66b3f13d3a71b957c0e646c0a0.js, 20160921_f1cc02f488792b7161849f8d15549315.js, 20160922_b22dda4c9fbc74ba5e251fc3110ada5a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4635f6ab0f307c878451c2e13b93f8c364364fd9dbd9b0a493d7990bc3eb3c17"
    hash2       = "77e753e21a464bef9fad04f7d41ce8b192c797808ff1b22efe474c612c25f2b2"
    hash3       = "a4438fd9b6e1eb385945338a0e8eaf272adfda2172cb3659bc36af2d1cc76ce5"
    hash4       = "946b208e84c64dbffc7e1cb08a19f629639d795decea5bf8ddd08b34a59e5e59"

  strings:
    $s1 = "y\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";})(),(function" ascii
    $s2 = "f000(){return \"Oe\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Mt" ascii
    $s3 = "urn \"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Tn\";})(),(f" ascii
    $s4 = "function f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Yz\";})(),(function f000(){ret" ascii
    $s5 = "ion f000(){return \"Iq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}